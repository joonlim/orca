/*
 * Copyright 2014 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.spinnaker.orca.controllers

import com.fasterxml.jackson.databind.ObjectMapper
import com.netflix.spinnaker.fiat.shared.FiatPermissionEvaluator
import com.netflix.spinnaker.orca.ExecutionStatus
import com.netflix.spinnaker.orca.front50.Front50Service
import com.netflix.spinnaker.orca.front50.model.Application
import com.netflix.spinnaker.orca.model.OrchestrationViewModel
import com.netflix.spinnaker.orca.pipeline.ExecutionRunner
import com.netflix.spinnaker.orca.pipeline.StageDefinitionBuilder
import com.netflix.spinnaker.orca.pipeline.model.Execution
import com.netflix.spinnaker.orca.pipeline.model.Execution.ExecutionType
import com.netflix.spinnaker.orca.pipeline.model.Stage
import com.netflix.spinnaker.orca.pipeline.model.Trigger
import com.netflix.spinnaker.orca.pipeline.persistence.ExecutionRepository
import com.netflix.spinnaker.orca.pipeline.util.ContextParameterProcessor
import com.netflix.spinnaker.security.AuthenticatedRequest
import groovy.transform.InheritConstructors
import groovy.util.logging.Slf4j
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.security.access.prepost.PostAuthorize
import org.springframework.security.access.prepost.PostFilter
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.access.prepost.PreFilter
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.*
import rx.schedulers.Schedulers

import java.time.Clock
import java.util.stream.Collectors

import static com.netflix.spinnaker.orca.pipeline.model.Execution.ExecutionType.ORCHESTRATION
import static com.netflix.spinnaker.orca.pipeline.model.Execution.ExecutionType.PIPELINE
import static java.time.ZoneOffset.UTC

@Slf4j
@RestController
class TaskController {
  @Autowired(required = false)
  Front50Service front50Service

  @Autowired
  ExecutionRepository executionRepository

  @Autowired
  ExecutionRunner executionRunner

  @Autowired
  Collection<StageDefinitionBuilder> stageBuilders

  @Autowired
  ContextParameterProcessor contextParameterProcessor

  @Autowired(required = false)
  FiatPermissionEvaluator permissionEvaluator

  @Autowired
  ObjectMapper mapper // autowired?

  @Value('${tasks.daysOfExecutionHistory:14}')
  int daysOfExecutionHistory

  @Value('${tasks.numberOfOldPipelineExecutionsToInclude:2}')
  int numberOfOldPipelineExecutionsToInclude

  Clock clock = Clock.systemUTC()

  @PreAuthorize("hasPermission(#application, 'APPLICATION', 'READ')")
  @RequestMapping(value = "/applications/{application}/tasks", method = RequestMethod.GET)
  List<OrchestrationViewModel> list(
    @PathVariable String application,
    @RequestParam(value = "page", defaultValue = "1") int page,
    @RequestParam(value = "limit", defaultValue = "3500") int limit,
    @RequestParam(value = "statuses", required = false) String statuses
  ) {
    statuses = statuses ?: ExecutionStatus.values()*.toString().join(",")
    def executionCriteria = new ExecutionRepository.ExecutionCriteria()
      .setPage(page)
      .setLimit(limit)
      .setStatuses(statuses.split(",") as Collection)

    def startTimeCutoff = clock
      .instant()
      .atZone(UTC)
      .minusDays(daysOfExecutionHistory)
      .toInstant()
      .toEpochMilli()

    def orchestrations = executionRepository
      .retrieveOrchestrationsForApplication(application, executionCriteria)
      .filter({ Execution orchestration -> !orchestration.startTime || (orchestration.startTime > startTimeCutoff) })
      .map({ Execution orchestration -> convert(orchestration) })
      .subscribeOn(Schedulers.io())
      .toList()
      .toBlocking()
      .single()
      .sort(startTimeOrId)

    orchestrations.subList(0, Math.min(orchestrations.size(), limit))
  }

  @PreAuthorize("@fiatPermissionEvaluator.storeWholePermission()")
  @PostFilter("hasPermission(filterObject.application, 'APPLICATION', 'READ')")
  @RequestMapping(value = "/tasks", method = RequestMethod.GET)
  List<OrchestrationViewModel> list() {
    executionRepository.retrieve(ORCHESTRATION).toBlocking().iterator.collect {
      convert it
    }
  }

  // @PostAuthorize("hasPermission(returnObject.application, 'APPLICATION', 'READ')")
  //
  // This endpoint is unsecured because of the create application process, where Deck immediately
  // queries this endpoint to check on the status of creating a new application before the
  // application permissions have been propagated. Furthermore, given that the ID is a hard-to-guess
  // GUID, it's unlikely than an attacker would be able to guess the identifier for any task.
  @RequestMapping(value = "/tasks/{id}", method = RequestMethod.GET)
  OrchestrationViewModel getTask(@PathVariable String id) {
    convert executionRepository.retrieve(ORCHESTRATION, id)
  }

  Execution getOrchestration(String id) {
    executionRepository.retrieve(ORCHESTRATION, id)
  }

  @PreAuthorize("hasPermission(this.getOrchestration(#id)?.application, 'APPLICATION', 'WRITE')")
  @RequestMapping(value = "/tasks/{id}", method = RequestMethod.DELETE)
  void deleteTask(@PathVariable String id) {
    executionRepository.retrieve(ORCHESTRATION, id).with {
      if (it.status.complete) {
        executionRepository.delete(ORCHESTRATION, id)
      } else {
        log.warn("Not deleting $ORCHESTRATION $id as it is $it.status")
        throw new CannotDeleteRunningExecution(ORCHESTRATION, id)
      }
    }
  }

  @PreAuthorize("hasPermission(this.getOrchestration(#id)?.application, 'APPLICATION', 'WRITE')")
  @RequestMapping(value = "/tasks/{id}/cancel", method = RequestMethod.PUT)
  @ResponseStatus(HttpStatus.ACCEPTED)
  void cancelTask(@PathVariable String id) {
    executionRepository.cancel(ORCHESTRATION, id, AuthenticatedRequest.getSpinnakerUser().orElse("anonymous"), null)
    executionRepository.updateStatus(ORCHESTRATION, id, ExecutionStatus.CANCELED)
  }

  @PreFilter("hasPermission(this.getOrchestration(filterObject)?.application, 'APPLICATION', 'WRITE')")
  @RequestMapping(value = "/tasks/cancel", method = RequestMethod.PUT)
  @ResponseStatus(HttpStatus.ACCEPTED)
  void cancelTasks(@RequestBody List<String> taskIds) {
    taskIds.each {
      executionRepository.cancel(ORCHESTRATION, it, AuthenticatedRequest.getSpinnakerUser().orElse("anonymous"), null)
      executionRepository.updateStatus(ORCHESTRATION, it, ExecutionStatus.CANCELED)
    }
  }

  @RequestMapping(value = "/pipelines", method = RequestMethod.GET)
  List<Execution> listLatestPipelines(
    @RequestParam(value = "pipelineConfigIds") String pipelineConfigIds,
    @RequestParam(value = "limit", required = false) Integer limit,
    @RequestParam(value = "statuses", required = false) String statuses) {
    statuses = statuses ?: ExecutionStatus.values()*.toString().join(",")
    limit = limit ?: 1
    def executionCriteria = new ExecutionRepository.ExecutionCriteria(
      limit: limit,
      statuses: (statuses.split(",") as Collection)
    )

    def ids = pipelineConfigIds.split(',')

    def allPipelines = rx.Observable.merge(ids.collect {
      executionRepository.retrievePipelinesForPipelineConfigId(it, executionCriteria)
    }).subscribeOn(Schedulers.io()).toList().toBlocking().single().sort(startTimeOrId)

    return filterPipelinesByHistoryCutoff(allPipelines, limit)
  }

  private boolean recursivelyCheckIfContainsFields(Object object, Object subset) {
    if (String.isInstance(object) && String.isInstance(subset)) {
      return ((String) object).matches((String) subset)
    } else if (Map.isInstance(object) && Map.isInstance(subset)) {
      Map objectMap = (Map) object
      Map subsetMap = (Map) subset
      Set subsetKeySet = new HashSet(subsetMap.keySet())
      for (Object subsetKey : subsetKeySet) {
        if (!recursivelyCheckIfContainsFields(objectMap.get(subsetKey), subsetMap.get(subsetKey))) {
          return false
        } else {
          subsetMap.remove(subsetKey)
        }
      }
      return true
    } else if (Collection.isInstance(object) && Collection.isInstance(subset)) {
      Set objectSet = new HashSet<>((Collection) object)
      Set subsetSet = new HashSet<>((Collection) subset)
      log.info("subseset {}", subsetSet)
      for (Object subsetSetObject : subsetSet) {
        boolean matched = false
        for (Object objectSetObject : objectSet) {
          if (Map.isInstance(subsetSetObject)) {
            subsetSetObject = new HashMap((Map) subsetSetObject)
          }
          if (recursivelyCheckIfContainsFields(objectSetObject, subsetSetObject)) {
            log.info("here1 {}", objectSetObject)
            log.info("here2 {}", subsetSetObject)
            objectSet.remove(objectSetObject)
            matched = true
            break
          }
        }
        if (!matched) {
          return false
        }
      }
      return true
//    } else if (Collection.isInstance(subset)) {
//      Map objectMap = mapper.convertValue(object, Map.class)
//      Map subsetMap = (Map) subset
//      for (Object subsetKey : subsetMap.keySet()) {
//        if (!recursivelyCheckIfContainsFields(objectMap.get(subsetKey), subsetMap.get(subsetKey))) {
//          return false
//        }
//      }
//      return true
      // todo: what about array?
    } else {
      return object == subset
    }
  }

  private boolean recursivelyCheckIfContainsFields2(Object object, Object subset) {
    if (String.isInstance(object) && String.isInstance(subset)) {
      return ((String) object).matches((String) subset)
    } else if (Map.isInstance(object) && Map.isInstance(subset)) {
      Map objectMap = (Map) object
      Map subsetMap = (Map) subset
      Set subsetKeySet = new HashSet(subsetMap.keySet())
      for (Object subsetKey : subsetKeySet) {
        if (!recursivelyCheckIfContainsFields(objectMap.get(subsetKey), subsetMap.get(subsetKey))) {
          return false
        } else {
//          subsetMap.remove(subsetKey)
        }
      }
      return true
    } else if (Collection.isInstance(object) && Collection.isInstance(subset)) {
      Set objectSet = new HashSet<>((Collection) object)
      Set subsetSet = new HashSet<>((Collection) subset)
      for (Object subsetSetObject : subsetSet) {
        boolean matched = false
        for (Object objectSetObject : objectSet) {
          if (recursivelyCheckIfContainsFields(objectSetObject, subsetSetObject)) {
            objectSet.remove(objectSetObject)
            matched = true
            continue
          }
        }
        if (!matched) {
          return false
        }
      }
      return true
//    } else if (Collection.isInstance(subset)) {
//      Map objectMap = mapper.convertValue(object, Map.class)
//      Map subsetMap = (Map) subset
//      for (Object subsetKey : subsetMap.keySet()) {
//        if (!recursivelyCheckIfContainsFields(objectMap.get(subsetKey), subsetMap.get(subsetKey))) {
//          return false
//        }
//      }
//      return true
      // todo: what about array?
    } else {
      return object == subset
    }
  }
//  boolean containsTriggerFields(Trigger trigger, Map fieldsToContain) {
//    for (String checkKey : fieldsToContain.keySet()) {
//      Object checkValue = fieldsToContain.get(checkKey)
//      Object triggerValue
//      switch (checkKey) {
//        case "type":
//          triggerValue = trigger.getType()
//          break
//        case "correlationId": // Keel correlation ID
//          triggerValue = trigger.getCorrelationId()
//          break
//        case "user":
//          triggerValue = trigger.getUser()
//          break
//        case "parameters":
//          triggerValue = trigger.getParameters()
//          break
//        case "artifacts":
//          triggerValue = trigger.getArtifacts()
//          break
//        case "notifications":
//          triggerValue = trigger.getNotifications()
//          break
//        case "isRebake":
//          triggerValue = trigger.isRebake()
//          break
//        case "isDryRun":
//          triggerValue = trigger.isDryRun()
//          break
    // isStrategy
//        case "resolvedExpectedArtifacts":
//          triggerValue = trigger.getResolvedExpectedArtifacts()
//          break
    //
//        default:
//          // "other"
//          triggerValue = trigger.getOther().get("key")
//      }
//      if (!recursivelyCheckIfContainsFields(triggerValue, checkValue)) {
//        return false
//      }
//    }
//    return true
//  }

  @RequestMapping(value = "/pipelines/search", method = RequestMethod.GET)
  List<Execution> searchForPipelineExecutions(
    @RequestParam(value = "application", required = false) String application,
    @RequestParam(value = "statuses", required = false) String statuses,
    @RequestParam(value = "buildTimeStartBoundary", defaultValue = "0") long buildTimeStartBoundary,
    @RequestParam(value = "buildTimeEndBoundary", defaultValue = "9223372036854775807" /* Long.MAX_VALUE */) long buildTimeEndBoundary,
    @RequestParam(value = "paginationStartIndex", defaultValue =  "0") int paginationStartIndex,
    @RequestParam(value = "resultsSize", defaultValue = "10") int resultsSize,
    @RequestParam(value = "reverse", defaultValue = "false") boolean reverse,
    @RequestParam(value = "expand", defaultValue = "false") boolean expand,
    @RequestBody (required=false) Map body,
    @RequestParam Map<String, String> params
  ) {
//    Map artifacts = new HashMap<>()
//    artifacts.put("name", "myartifact")
//    params.put("trigger_artifacts", Arrays.asList(artifacts))
    log.error("start ===============================================================")
    log.error("application: {}", application)
    log.error("statuses: {}", statuses)
    log.error("buildTimeStartBoundary: {}", buildTimeStartBoundary)
    log.error("buildTimeEndBoundary: {}", buildTimeEndBoundary)
    log.error("paginationStartIndex: {}", paginationStartIndex)
    log.error("resultsSize: {}", resultsSize)
    log.error("reverse: {}", reverse)
    log.error("expand: {}", expand)
    log.error("params: {}", params)
    log.error("VALIDATING INPUT ====================================================")

    statuses = statuses ?: ExecutionStatus.values()*.toString().join(",")

    if (buildTimeStartBoundary < 0) {
      throw new RuntimeException(String.format("buildTimeStartBoundary must be >= 0: buildTimeStartBoundary=%s", buildTimeStartBoundary))
    }
    if (buildTimeEndBoundary < 0) {
      throw new RuntimeException(String.format("buildTimeEndBoundary must be >= 0: buildTimeEndBoundary=%s", buildTimeEndBoundary))
    }
    if (buildTimeStartBoundary > buildTimeEndBoundary) {
      throw new RuntimeException(String.format("buildTimeStartBoundary must be <= buildTimeEndBoundary: buildTimeStartBoundary=%s, buildTimeEndBoundary=%s", buildTimeStartBoundary, buildTimeEndBoundary))
    }

    log.error("buildTimeStartBoundary: %s", buildTimeStartBoundary)
    log.error("buildTimeEndBoundary: %s", buildTimeEndBoundary)

    if (paginationStartIndex < 0) {
      throw new RuntimeException(String.format("paginationStartIndex must be >= 0: paginationStartIndex=%s", paginationStartIndex))
    }
    if (resultsSize <= 0) {
      throw new RuntimeException(String.format("resultsSize must be > 0: resultsSize=%s", resultsSize))
    }

    Map triggerParams = new HashMap()
    for (String key : params.keySet()) {
      if (key.startsWith("trigger_") && key.length() > "trigger_".length()) {
        triggerParams.put(key.substring("trigger_".length()), params.get(key))
      }
    }
    for (String key : body.keySet()) {
      triggerParams.put(key, body.get(key))
    }
    log.error("triggerParams: {}", triggerParams)

    log.error("LOAD EXECUTIONS =====================================================")

    ExecutionRepository.ExecutionCriteria executionCriteria = new ExecutionRepository.ExecutionCriteria(
      limit: Integer.MAX_VALUE,
      statuses: (statuses.split(",") as Collection),
      buildTimeStartBoundary: buildTimeStartBoundary,
      buildTimeEndBoundary: buildTimeEndBoundary
    )

    List<String> applicationNames = application ? [application] : front50Service.getAllApplications()*.name as List<String>
    log.error("applicationNames: {}", applicationNames)
    List<String> pipelineConfigIds = getPipelineConfigIdsOfReadableApplications(applicationNames)

    log.error("pipelineConfigIds: {}", pipelineConfigIds)

    List<Execution> pipelineExecutions = rx.Observable.merge(pipelineConfigIds.collect {
      // TODO: It may make sense to periodically cache the results of retrievePipelinesForPipelineConfigId
      executionRepository.retrievePipelinesForPipelineConfigId(it, executionCriteria).filter { pipelineExecution ->
        Map pipelineExecutionAsMap = mapper.convertValue(pipelineExecution.getTrigger(), Map.class)
        Map triggerParamsCopy = new HashMap(triggerParams)
        return recursivelyCheckIfContainsFields(pipelineExecutionAsMap, triggerParamsCopy) ||
          (pipelineExecutionAsMap.containsKey("payload") && recursivelyCheckIfContainsFields2(pipelineExecutionAsMap.get("payload"), triggerParamsCopy))
      }
    }).subscribeOn(Schedulers.io())
      .toList()
      .toBlocking()
      .single()
      .sort(startTimeOrId)


//    List<Execution> pipelineExecutions = rx.Observable.merge(pipelineConfigIds.collect {
////      executionRepository.retrievePipelinesForPipelineConfigId(it, executionCriteria).filter { pipelineExecution -> containsTriggerFields(pipelineExecution.getTrigger(), body) }
//      executionRepository.retrievePipelinesForPipelineConfigId(it, executionCriteria)
//    }).subscribeOn(Schedulers.io())
//    .filter{ pipelineExecution ->
//        if (body != null) {
//          return recursivelyCheckIfContainsFields(mapper.convertValue(pipelineExecution.getTrigger(), Map.class), body)
//        } else {
//          return true
//        }
//      }.subscribeOn(Schedulers.computation())
//      .toList()
//      .toBlocking()
//      .single()
//      .sort(startTimeOrId)

    log.error("REVERSE =============================================================")

    if (reverse) {
      pipelineExecutions.reverse(true)
    }

    log.error("PAGINATE ============================================================")

    if (paginationStartIndex >= pipelineExecutions.size()) {
      pipelineExecutions = []
    } else {
      pipelineExecutions = pipelineExecutions.subList(paginationStartIndex, Math.min(pipelineExecutions.size(), paginationStartIndex + resultsSize))
    }

    log.error("UNEXPAND ============================================================")

    if (!expand) {
      unexpandPipelineExecutions(pipelineExecutions)
    }

    log.error("end =================================================================")
    return pipelineExecutions
  }

  // TODO(joonlim)
  @RequestMapping(value = "/pipelines/trigger", method = RequestMethod.GET)
  List<Execution> listLatestPipelineExecutionsWithPayload(
    @RequestBody List<Map<String, String>> body, // payloadParamsSubset
    @RequestParam(value = "limit", defaultValue = "5") Integer limit,
    @RequestParam(value = "statuses", required = false) String statuses
  ) {
    // validate input
    if (body.size() == 0) {
      // throw exception?
      return []
    }
    for (Map<String, String> payloadDescription : body) {
      if (payloadDescription.size() == 0) {
        return []
      }
    }

    statuses = statuses ?: ExecutionStatus.values()*.toString().join(",")
    def executionCriteria = new ExecutionRepository.ExecutionCriteria(
      limit: limit,
      statuses: (statuses.split(",") as Collection)
    )

    // Auth logic
    // get all applications
    Authentication auth = SecurityContextHolder.context.authentication
    def allIds = []
    for (Application application : front50Service.getAllApplications()) {
      if (permissionEvaluator && !permissionEvaluator.hasPermission(auth, application.name, 'APPLICATION', 'READ')) {
        continue
      }

      def pipelineConfigIds = front50Service.getPipelines(application.name, false)*.id as List<String>
      def strategyConfigIds = front50Service.getStrategies(application.name)*.id as List<String>
      allIds = allIds + pipelineConfigIds + strategyConfigIds // scales?
    }

    // all ids
//    def pipelineConfigIds = front50Service.getAllPipelines()*.id as List<String>
//    def strategyConfigIds = front50Service.getAllStrategies()*.id as List<String>
//    def allIds = pipelineConfigIds + strategyConfigIds

    def allPipelines = rx.Observable.merge(allIds.collect {
      executionRepository.retrievePipelinesForPipelineConfigId(it, executionCriteria).filter { pipeline ->
        Map<String, String> payload = pipeline.getTrigger().getOther().get("payload")
        if (payload == null || payload.size() == 0) {
          return false
        }

        // Check each input payload description to see if any of them match
        for (Map<String, String> payloadDescription : body) {
          boolean allMatched = true
          for (String key : payloadDescription.keySet()) {
            if (payload.get(key) != payloadDescription.get(key)) {
              allMatched = false
              break
            }
          }
          if (allMatched) {
            return true
          }
        }
        return false // all payload descriptions don't match

        // filter by each param
//        for (String key : parameters.keySet()) {
//          Map<String, String> payload = pipeline.getTrigger().getOther().get("payload");
//          if (parameters.get(key) != payload.get(key)) {
//            return false
//          }
//        }
//        return true
      }
    }).subscribeOn(Schedulers.io()).toList().toBlocking().single().sort(startTimeOrId)

    return filterPipelinesByHistoryCutoff(allPipelines, limit)
  }

  // TODO(joonlim)
  @RequestMapping(value = "/pipelines/artifact", method = RequestMethod.GET)
  List<Execution> listLatestPipelineExecutionsWithArtifact(
    @RequestBody Map<String, String> artifactParamsSubset,
    @RequestParam(value = "limit", defaultValue = "5") Integer limit,
    @RequestParam(value = "statuses", required = false) String statuses
  ) {
    // validate input
    if (artifactParamsSubset.size() == 0) {
      // throw exception?
      return []
    }
    if (artifactParamsSubset.size() == 0) {
      return []
    }

    statuses = statuses ?: ExecutionStatus.values()*.toString().join(",")
    def executionCriteria = new ExecutionRepository.ExecutionCriteria(
      limit: limit,
      statuses: (statuses.split(",") as Collection)
    )

    // Auth logic
    // get all applications
    Authentication auth = SecurityContextHolder.context.authentication
    def allIds = []
    for (Application application : front50Service.getAllApplications()) {
      if (permissionEvaluator && !permissionEvaluator.hasPermission(auth, application.name, 'APPLICATION', 'READ')) {
        continue
      }

      def pipelineConfigIds = front50Service.getPipelines(application.name, false)*.id as List<String>
      def strategyConfigIds = front50Service.getStrategies(application.name)*.id as List<String>
      allIds = allIds + pipelineConfigIds + strategyConfigIds // scales?
    }

    def allPipelines = rx.Observable.merge(allIds.collect {
      executionRepository.retrievePipelinesForPipelineConfigId(it, executionCriteria).filter { pipeline ->
        List<Map<String, String>> artifacts = pipeline.getTrigger().getArtifacts();
        if (artifacts == null || artifacts.isEmpty()) {
          return false;
        }

        for (Map<String, String> artifact : artifacts) {
          boolean allMatched = true
          for (String key : artifactParamsSubset.keySet()) {
            if (artifact.get(key) != artifactParamsSubset.get(key)) {
              allMatched = false
              break
            }
          }
          if (allMatched) {
            return true
          }
        }
        return false
      }
    }).subscribeOn(Schedulers.io()).toList().toBlocking().single().sort(startTimeOrId)

    return filterPipelinesByHistoryCutoff(allPipelines, limit)
  }

  /**
   * Grab pipeline executions triggered with a triggerCorrelationId
   * @param triggerCorrelationId
   * @param limit
   * @param statuses
   * @return
   */
  // TODO(joonlim)
  @RequestMapping(value = "/pipelines/webhook", method = RequestMethod.GET)
  List<Execution> listPipelineExecutionsTriggeredByWebhook(
    @RequestParam(value = "triggerCorrelationId") String triggerCorrelationId,
    @RequestParam(value = "limit", defaultValue = "5") Integer limit,
    @RequestParam(value = "statuses", required = false) String statuses
  ) {
    statuses = statuses ?: ExecutionStatus.values()*.toString().join(",")
    def executionCriteria = new ExecutionRepository.ExecutionCriteria(
      limit: limit,
      statuses: (statuses.split(",") as Collection)
    )

    // Auth logic
    // get all applications
    Authentication auth = SecurityContextHolder.context.authentication
    def allIds = []
    for (Application application : front50Service.getAllApplications()) {
      if (permissionEvaluator && !permissionEvaluator.hasPermission(auth, application.name, 'APPLICATION', 'READ')) {
        continue
      }

      def pipelineConfigIds = front50Service.getPipelines(application.name, false)*.id as List<String>
      def strategyConfigIds = front50Service.getStrategies(application.name)*.id as List<String>
      allIds = allIds + pipelineConfigIds + strategyConfigIds // scales?
    }

    // all ids
//    def pipelineConfigIds = front50Service.getAllPipelines()*.id as List<String>
//    def strategyConfigIds = front50Service.getAllStrategies()*.id as List<String>
//    def allIds = pipelineConfigIds + strategyConfigIds

    def allPipelines = rx.Observable.merge(allIds.collect {
      executionRepository.retrievePipelinesForPipelineConfigId(it, executionCriteria).filter { pipeline ->
        pipeline.getTrigger().getOther().get("triggerCorrelationId") == triggerCorrelationId
      }
    }).subscribeOn(Schedulers.io()).toList().toBlocking().single().sort(startTimeOrId)

    return filterPipelinesByHistoryCutoff(allPipelines, limit)
  }

  // TODO(joonlim)
  // filters by trigger type
  @RequestMapping(value = "/applications/{application}/pipelines/trigger", method = RequestMethod.GET)
  List<Execution> listLatestPipelinesForTrigger(
    @PathVariable String application,
    @RequestBody Trigger trigger,
    @RequestParam(value = "limit", defaultValue = "5") Integer limit,
    @RequestParam(value = "statuses", required = false) String statuses) {

    statuses = statuses ?: ExecutionStatus.values()*.toString().join(",")
    def executionCriteria = new ExecutionRepository.ExecutionCriteria(
      limit: limit,
      statuses: (statuses.split(",") as Collection)
    )

    def pipelineConfigIds = front50Service.getPipelines(application, false)*.id as List<String>
    // def strategyConfigIds = front50Service.getStrategies(application)*.id as List<String>
    def allIds = pipelineConfigIds// + strategyConfigIds

    def allPipelines = rx.Observable.merge(allIds.collect {
      executionRepository.retrievePipelinesForPipelineConfigId(it, executionCriteria).filter { pipeline ->
        // event id
        pipeline.getTrigger().getType() == trigger.getType()
        // TODO: create closure for this.
        // TriggerSubsetMatcher
      }
    }).subscribeOn(Schedulers.io()).toList().toBlocking().single().sort(startTimeOrId)

//    allPipelines.each { pipeline ->
//      clearTriggerStages(pipeline.trigger.other) // remove from the "other" field - that is what Jackson works against
//      pipeline.getStages().each { stage ->
//        if (stage.context?.group) {
//          // TODO: consider making "group" a top-level field on the Stage model
//          // for now, retain group in the context, as it is needed for collapsing templated pipelines in the UI
//          stage.context = [ group: stage.context.group ]
//        } else {
//          stage.context = [:]
//        }
//        stage.outputs = [:]
//        stage.tasks = []
//      }
//    }

    return filterPipelinesByHistoryCutoff(allPipelines, limit)
  }

  @PostAuthorize("hasPermission(returnObject.application, 'APPLICATION', 'READ')")
  @RequestMapping(value = "/pipelines/{id}", method = RequestMethod.GET)
  Execution getPipeline(@PathVariable String id) {
    executionRepository.retrieve(PIPELINE, id)
  }

  @PreAuthorize("hasPermission(this.getPipeline(#id)?.application, 'APPLICATION', 'WRITE')")
  @RequestMapping(value = "/pipelines/{id}", method = RequestMethod.DELETE)
  void deletePipeline(@PathVariable String id) {
    executionRepository.retrieve(PIPELINE, id).with {
      if (it.status.complete) {
        executionRepository.delete(PIPELINE, id)
      } else {
        log.warn("Not deleting $PIPELINE $id as it is $it.status")
        throw new CannotDeleteRunningExecution(PIPELINE, id)
      }
    }
  }

  @PreAuthorize("hasPermission(this.getPipeline(#id)?.application, 'APPLICATION', 'WRITE')")
  @RequestMapping(value = "/pipelines/{id}/cancel", method = RequestMethod.PUT)
  @ResponseStatus(HttpStatus.ACCEPTED)
  void cancel(
    @PathVariable String id, @RequestParam(required = false) String reason,
    @RequestParam(defaultValue = "false") boolean force) {
    executionRepository.retrieve(PIPELINE, id).with { pipeline ->
      executionRunner.cancel(
        pipeline,
        AuthenticatedRequest.getSpinnakerUser().orElse("anonymous"),
        reason
      )
    }
    executionRepository.updateStatus(PIPELINE, id, ExecutionStatus.CANCELED)
  }

  @PreAuthorize("hasPermission(this.getPipeline(#id)?.application, 'APPLICATION', 'WRITE')")
  @RequestMapping(value = "/pipelines/{id}/pause", method = RequestMethod.PUT)
  @ResponseStatus(HttpStatus.ACCEPTED)
  void pause(@PathVariable String id) {
    executionRepository.pause(PIPELINE, id, AuthenticatedRequest.getSpinnakerUser().orElse("anonymous"))
    def pipeline = executionRepository.retrieve(PIPELINE, id)
    executionRunner.reschedule(pipeline)
  }

  @PreAuthorize("hasPermission(this.getPipeline(#id)?.application, 'APPLICATION', 'WRITE')")
  @RequestMapping(value = "/pipelines/{id}/resume", method = RequestMethod.PUT)
  @ResponseStatus(HttpStatus.ACCEPTED)
  void resume(@PathVariable String id) {
    executionRepository.resume(PIPELINE, id, AuthenticatedRequest.getSpinnakerUser().orElse("anonymous"))
    def pipeline = executionRepository.retrieve(PIPELINE, id)
    executionRunner.unpause(pipeline)
  }

  @PreAuthorize("@fiatPermissionEvaluator.storeWholePermission()")
  @PostFilter("hasPermission(this.getPipeline(filterObject)?.application, 'APPLICATION', 'READ')")
  @RequestMapping(value = "/pipelines/running", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.GONE)
  List<String> runningPipelines() {
    []
  }

  @PreAuthorize("@fiatPermissionEvaluator.storeWholePermission()")
  @PostFilter("hasPermission(this.getPipeline(filterObject)?.application, 'APPLICATION', 'READ')")
  @RequestMapping(value = "/pipelines/waiting", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.GONE)
  List<String> waitingPipelines() {
    []
  }

  @PreAuthorize("hasPermission(this.getPipeline(#id)?.application, 'APPLICATION', 'WRITE')")
  @RequestMapping(value = "/pipelines/{id}/stages/{stageId}", method = RequestMethod.PATCH)
  Execution updatePipelineStage(
    @PathVariable String id,
    @PathVariable String stageId, @RequestBody Map context) {
    def pipeline = executionRepository.retrieve(PIPELINE, id)
    def stage = pipeline.stages.find { it.id == stageId }
    if (stage) {
      stage.context.putAll(context)

      stage.lastModified = new Stage.LastModifiedDetails(
        user: AuthenticatedRequest.getSpinnakerUser().orElse("anonymous"),
        allowedAccounts: AuthenticatedRequest.getSpinnakerAccounts().orElse(null)?.split(",") ?: [],
        lastModifiedTime: System.currentTimeMillis()
      )

      // `lastModifiedBy` is deprecated (pending a update to deck)
      stage.context["lastModifiedBy"] = AuthenticatedRequest.getSpinnakerUser().orElse("anonymous")

      executionRepository.storeStage(stage)

      executionRunner.reschedule(pipeline)
    }
    pipeline
  }

  @PreAuthorize("hasPermission(this.getPipeline(#id)?.application, 'APPLICATION', 'WRITE')")
  @RequestMapping(value = "/pipelines/{id}/stages/{stageId}/restart", method = RequestMethod.PUT)
  Execution retryPipelineStage(
    @PathVariable String id, @PathVariable String stageId) {
    def pipeline = executionRepository.retrieve(PIPELINE, id)
    executionRunner.restart(pipeline, stageId)
    pipeline
  }

  @PreAuthorize("hasPermission(this.getPipeline(#id)?.application, 'APPLICATION', 'READ')")
  @RequestMapping(value = "/pipelines/{id}/evaluateExpression", method = RequestMethod.GET)
  Map evaluateExpressionForExecution(@PathVariable("id") String id,
                                     @RequestParam("expression")
                                       String expression) {
    def execution = executionRepository.retrieve(PIPELINE, id)
    def evaluated = contextParameterProcessor.process(
      [expression: expression],
      [execution: execution],
      true
    )
    return [result: evaluated?.expression, detail: evaluated?.expressionEvaluationSummary]
  }

  // TODO(joonlim): search for all pipelines
  // Should be called pipeline executions?
  @PreAuthorize("hasPermission(#application, 'APPLICATION', 'READ')")
  @RequestMapping(value = "/v2/applications/{application}/pipelines", method = RequestMethod.GET)
  List<Execution> getApplicationPipelines(@PathVariable String application,
                                          @RequestParam(value = "limit", defaultValue = "5")
                                            int limit,
                                          @RequestParam(value = "statuses", required = false)
                                            String statuses,
                                         @RequestParam(value = "expand", defaultValue = "true") Boolean expand) {
    return getPipelinesForApplication(application, limit, statuses, expand)
  }

  @PreAuthorize("hasPermission(#application, 'APPLICATION', 'READ')")
  @RequestMapping(value = "/applications/{application}/pipelines", method = RequestMethod.GET)
  List<Execution> getPipelinesForApplication(@PathVariable String application,
                                             @RequestParam(value = "limit", defaultValue = "5")
                                               int limit,
                                             @RequestParam(value = "statuses", required = false)
                                               String statuses,
                                            @RequestParam(value = "expand", defaultValue = "true") Boolean expand) {
    if (!front50Service) {
      throw new UnsupportedOperationException("Cannot lookup pipelines, front50 has not been enabled. Fix this by setting front50.enabled: true")
    }

    if (!limit) {
      return []
    }

    statuses = statuses ?: ExecutionStatus.values()*.toString().join(",")
    def executionCriteria = new ExecutionRepository.ExecutionCriteria(
      limit: limit,
      statuses: (statuses.split(",") as Collection)
    )

    def pipelineConfigIds = front50Service.getPipelines(application, false)*.id as List<String>
    def strategyConfigIds = front50Service.getStrategies(application)*.id as List<String>
    def allIds = pipelineConfigIds + strategyConfigIds

    def allPipelines = rx.Observable.merge(allIds.collect {
      executionRepository.retrievePipelinesForPipelineConfigId(it, executionCriteria)
    }).subscribeOn(Schedulers.io()).toList().toBlocking().single().sort(startTimeOrId)

    if (!expand) {
      unexpandPipelineExecutions(allPipelines)
    }

    return filterPipelinesByHistoryCutoff(allPipelines, limit)
  }

  private List<String> getPipelineConfigIdsOfReadableApplications(List<String> applicationNames) {
    Authentication auth = SecurityContextHolder.context.authentication
    List<String> pipelineConfigIds = applicationNames.stream()
      .filter{ applicationName -> permissionEvaluator || permissionEvaluator.hasPermission(auth, applicationName, 'APPLICATION', 'READ') }
      .map{ applicationName -> front50Service.getPipelines(applicationName, false)*.id as List<String> }
      .flatMap{ c -> c.stream() }
      .collect(Collectors.toList())

    return pipelineConfigIds
  }

  private static void clearTriggerStages(Map trigger) {
    if (trigger.type.toLowerCase() != "pipeline") {
      return
    }
    ((List) trigger.parentExecution.stages).clear()
    if (trigger.parentExecution.trigger.type.toLowerCase() == "pipeline") {
      clearTriggerStages((Map) trigger.parentExecution.trigger)
    }
  }

  private List<Execution> filterPipelinesByHistoryCutoff(List<Execution> pipelines, int limit) {
    // TODO-AJ The eventual goal is to return `allPipelines` without the need to group + filter below (WIP)
    def cutoffTime = (new Date(clock.millis()) - daysOfExecutionHistory).time

    def pipelinesSatisfyingCutoff = []
    pipelines.groupBy {
      it.pipelineConfigId
    }.values().each { List<Execution> pipelinesGroup ->
      def sortedPipelinesGroup = pipelinesGroup.sort(startTimeOrId).reverse()
      def recentPipelines = sortedPipelinesGroup.findAll {
        !it.startTime || it.startTime > cutoffTime
      }
      if (!recentPipelines && sortedPipelinesGroup) {
        // no pipeline executions within `daysOfExecutionHistory` so include the first `numberOfOldPipelineExecutionsToInclude`
        def upperBounds = Math.min(sortedPipelinesGroup.size(), numberOfOldPipelineExecutionsToInclude) - 1
        recentPipelines = sortedPipelinesGroup[0..upperBounds]
      }

      pipelinesSatisfyingCutoff.addAll(recentPipelines.subList(0, Math.min(recentPipelines.size(), limit)))
    }

    return pipelinesSatisfyingCutoff.sort(startTimeOrId)
  }

  private static unexpandPipelineExecutions(List<Execution> pipelineExecutions) {
    pipelineExecutions.each { pipelineExecution ->
      clearTriggerStages(pipelineExecution.trigger.other) // remove from the "other" field - that is what Jackson works against
      pipelineExecution.getStages().each { stage ->
        if (stage.context?.group) {
          // TODO: consider making "group" a top-level field on the Stage model
          // for now, retain group in the context, as it is needed for collapsing templated pipelines in the UI
          stage.context = [ group: stage.context.group ]
        } else {
          stage.context = [:]
        }
        stage.outputs = [:]
        stage.tasks = []
      }
    }
  }

  private static Closure startTimeOrId = { a, b ->
    def aStartTime = a.startTime ?: 0
    def bStartTime = b.startTime ?: 0

    return aStartTime <=> bStartTime ?: b.id <=> a.id
  }

  private OrchestrationViewModel convert(Execution orchestration) {
    def variables = [:]
    for (stage in orchestration.stages) {
      for (entry in stage.context.entrySet()) {
        variables[entry.key] = entry.value
      }
    }
    new OrchestrationViewModel(
      id: orchestration.id,
      name: orchestration.description,
      application: orchestration.application,
      status: orchestration.getStatus(),
      variables: variables.collect { key, value ->
        [
          "key"  : key,
          "value": value
        ]
      },
      steps: orchestration.stages.tasks.flatten(),
      buildTime: orchestration.buildTime,
      startTime: orchestration.startTime,
      endTime: orchestration.endTime,
      execution: orchestration
    )
  }

  @InheritConstructors
  @ResponseStatus(HttpStatus.NOT_IMPLEMENTED)
  private static class FeatureNotEnabledException extends RuntimeException {}

  @ResponseStatus(HttpStatus.CONFLICT)
  private static class CannotDeleteRunningExecution extends RuntimeException {
    CannotDeleteRunningExecution(ExecutionType type, String id) {
      super("Cannot delete a running $type, please cancel it first.")
    }
  }
}
