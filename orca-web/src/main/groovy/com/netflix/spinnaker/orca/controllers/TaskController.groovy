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
import com.google.common.collect.Collections2
import com.netflix.spinnaker.orca.ExecutionStatus
import com.netflix.spinnaker.orca.front50.Front50Service
import com.netflix.spinnaker.orca.model.OrchestrationViewModel
import com.netflix.spinnaker.orca.pipeline.ExecutionRunner
import com.netflix.spinnaker.orca.pipeline.StageDefinitionBuilder
import com.netflix.spinnaker.orca.pipeline.model.Execution
import com.netflix.spinnaker.orca.pipeline.model.Execution.ExecutionType
import com.netflix.spinnaker.orca.pipeline.model.Stage
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
import org.springframework.web.bind.annotation.*
import rx.schedulers.Schedulers

import java.nio.charset.Charset
import java.time.Clock

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

  @Autowired
  ObjectMapper mapper

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

  /**
   * Search for pipeline executions using a combination of criteria.
   *
   * @param application Only includes executions that are part of this application.
   * @param triggerType Only includes executions that were triggered by a trigger with this type. If
   * this value is '*', includes executions with all trigger types.
   * @param eventId (optional) Only includes executions that were triggered by a trigger with this
   * eventId. This only applies to triggers that return a response message when called.
   * @param encodedTriggerParams (optional) Only includes executions that were triggered by a
   * trigger that matches the subset of fields provided by this value. This value should be a base64
   * encoded string of a JSON representation of a trigger object.
   * @param buildTimeStartBoundary (optional) Only includes executions that were built at or after
   * the given time, represented as a Unix timestamp in ms (UTC). This value must be >= 0 and <=
   * the value of [buildTimeEndBoundary], if provided. If this value is missing, it is defaulted to
   * 0.
   * @param buildTimeEndBoundary (optional) Only includes executions that were built at or before
   * the given time, represented as a Unix timestamp in ms (UTC). This value must be <=
   * 9223372036854775807 (Long.MAX_VALUE) and >= the value of [buildTimeStartBoundary], if provided.
   * If this value is missing, it is defaulted to 9223372036854775807.
   * @param statuses (optional) Only includes executions with a status that is equal to a status
   * provided in this field. The list of statuses should be given as a comma-delimited string. If
   * this value is missing, includes executions of all statuses. Allowed statuses are: NOT_STARTED,
   * RUNNING, PAUSED, SUSPENDED, SUCCEEDED, FAILED_CONTINUE, TERMINAL, CANCELED, REDIRECT, STOPPED,
   * SKIPPED, BUFFERED. @see com.netflix.spinnaker.orca.ExecutionStatus for more info.
   * @param page (optional) Sets the first item of the resulting list for pagination. The list is
   * 0-indexed. This value must be >= 0. If this value is missing, it is defaulted to 0.
   * @param pageSize (optional) Sets the size of the resulting list for pagination. This value must
   * be > 0. If this value is missing, it is defaulted to 10.
   * @param reverse (optional) Reverses the resulting list before it is paginated. If this value is
   * missing, it is defaulted to false.
   * @param expand (optional) Expands each execution object in the resulting list. If this value is
   * missing, it is defaulted to false.
   * @return
   */
  @PreAuthorize("hasPermission(#application, 'APPLICATION', 'READ')")
  @RequestMapping(value = "/pipelines/{application}/search/{triggerType}", method = RequestMethod.GET)
  List<Execution> searchForPipelineExecutions(
    @PathVariable(value = "application") String application,
    @PathVariable(value = "triggerType") String triggerType,
    @RequestParam(value = "eventId", required = false) String eventId,
    @RequestParam(value = "encodedTriggerParams", required = false) String encodedTriggerParams,
    @RequestParam(value = "buildTimeStartBoundary", defaultValue = "0") long buildTimeStartBoundary,
    @RequestParam(value = "buildTimeEndBoundary", defaultValue = "9223372036854775807" /* Long.MAX_VALUE */) long buildTimeEndBoundary,
    @RequestParam(value = "statuses", required = false) String statuses,
    @RequestParam(value = "page", defaultValue =  "0") int page,
    @RequestParam(value = "pageSize", defaultValue = "10") int pageSize,
    @RequestParam(value = "reverse", defaultValue = "false") boolean reverse,
    @RequestParam(value = "expand", defaultValue = "false") boolean expand
  ) {
    if (buildTimeStartBoundary < 0) {
      throw new RuntimeException(String.format("buildTimeStartBoundary must be >= 0: buildTimeStartBoundary=%s", buildTimeStartBoundary))
    }
    if (buildTimeEndBoundary < 0) {
      throw new RuntimeException(String.format("buildTimeEndBoundary must be >= 0: buildTimeEndBoundary=%s", buildTimeEndBoundary))
    }
    if (buildTimeStartBoundary > buildTimeEndBoundary) {
      throw new RuntimeException(String.format("buildTimeStartBoundary must be <= buildTimeEndBoundary: buildTimeStartBoundary=%s, buildTimeEndBoundary=%s", buildTimeStartBoundary, buildTimeEndBoundary))
    }
    if (page < 0) {
      throw new RuntimeException(String.format("page must be >= 0: page=%s", page))
    }
    if (pageSize <= 0) {
      throw new RuntimeException(String.format("pageSize must be > 0: pageSize=%s", pageSize))
    }

    Map triggerParams
    if (encodedTriggerParams != null) {
      byte[] decoded = Base64.getDecoder().decode(encodedTriggerParams)
      String str = new String(decoded, Charset.forName("UTF-8"))
      triggerParams = mapper.readValue(str, Map.class)
    } else {
      triggerParams = new HashMap()
    }

    if (triggerType != "*") {
      triggerParams.put("type", triggerType)
    }
    if (eventId != null) {
      triggerParams.put("eventId", eventId)
    }

    statuses = statuses ?: ExecutionStatus.values()*.toString().join(",")

    ExecutionRepository.BuildTimeBoundaryExecutionCriteria executionCriteria = new ExecutionRepository.BuildTimeBoundaryExecutionCriteria(
      buildTimeStartBoundary: buildTimeStartBoundary,
      buildTimeEndBoundary: buildTimeEndBoundary,
      statuses: (statuses.split(",") as Collection)
    )

    // TODO(joonlim): It may make sense in the future to allow a user to specify '*' as the application to search across all applications
    List<String> pipelineConfigIds = front50Service.getPipelines(application, false)*.id as List<String>

    List<Execution> pipelineExecutions = rx.Observable.merge(pipelineConfigIds.collect {
      executionRepository.retrievePipelinesForPipelineConfigIdWithBuildTimeBoundary(it, executionCriteria).filter {
        // Compare each execution's trigger to input triggerParams
        Map triggerAsMap = mapper.convertValue(it.getTrigger(), Map.class)
        return recursivelyCheckIfObjectFieldsMatchesAllSubsetFields(triggerAsMap, triggerParams)
      }
    }).subscribeOn(Schedulers.io())
      .toList()
      .toBlocking()
      .single()
      .sort(reverseBuildTime)

    if (reverse) {
      pipelineExecutions.reverse(true)
    }

    List<Execution> rval
    if (page >= pipelineExecutions.size()) {
      rval = []
    } else {
      rval = pipelineExecutions.subList(page, Math.min(pipelineExecutions.size(), page + pageSize))
    }

    if (!expand) {
      unexpandPipelineExecutions(rval)
    }

    return rval
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

  private static Closure reverseBuildTime = { a, b ->
    def aBuildTime = a.buildTime ?: 0
    def bBuildTime = b.buildTime ?: 0

    return bBuildTime <=> aBuildTime ?: b.id <=> a.id
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

  private static boolean recursivelyCheckIfObjectFieldsMatchesAllSubsetFields(Object object, Object subset) {
    if (String.isInstance(object) && String.isInstance(subset)) {
      // object matches subset if:
      // - object equals subset
      // - object matches subset as a regular expression
      return ((String) object).matches((String) subset)
    } else if (Map.isInstance(object) && Map.isInstance(subset)) {
      // object matches subset if:
      // - object contains all keys of subset and their values match
      Map objectAsMap = (Map) object
      Map subsetAsMap = (Map) subset
      for (Object key : subsetAsMap.keySet()) {
        if (!recursivelyCheckIfObjectFieldsMatchesAllSubsetFields(objectAsMap.get(key), subsetAsMap.get(key))) {
          return false
        }
      }
      return true
    } else if (Collection.isInstance(object) && Collection.isInstance(subset)) {
      // object matches subset if:
      // - object contains a unique item that matches each item in subset
      //   * this means that an item in subset may not match to more than one item in object, which
      //     means that we should check every permutation of object to avoid greedily stopping
      //     on the first item that matches.
      //     e.g., Given,
      //             object: [ { "name": "a", "version": "1" }, { "name" } ]
      //           Without checking all permutations, this will match:
      //             subset: [ { "name": "a", "version": "1" }, { "name" } ]
      //           but will not match:
      //             subset: [ { "name": "a" }, { "name", "version": "1" } ]
      //           because the first item in subset will greedily match the first item in object,
      //           leaving the second items in both, which do not match. This is fixed by checking
      //           all permutations of object.
      Collection<List> permutationsOfObjectAsList = Collections2.permutations((Collection) object)
      List subsetAsList = new ArrayList((Collection) subset)
      for (List objectAsList : permutationsOfObjectAsList) {
        objectAsList = new ArrayList(objectAsList) // this should be mutable because we will be removing items
        boolean matchedAllItems = true

        for (Object subsetItem : subsetAsList) {
          boolean matchedItem = false
          for (Object objectItem : objectAsList) {
            if (recursivelyCheckIfObjectFieldsMatchesAllSubsetFields(objectItem, subsetItem)) {
              objectAsList.remove(objectItem) // make sure to not match the same item more than once
              matchedItem = true
              break
            }
          }

          if (!matchedItem) {
            matchedAllItems = false
            break
          }
        }

        if (matchedAllItems) {
          return true
        }
      }

      // Failed to match for all permutations
      return false
    } else {
      return object == subset
    }
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
