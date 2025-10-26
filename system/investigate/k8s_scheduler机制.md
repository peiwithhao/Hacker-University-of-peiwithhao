# kube-scheduler调度机制

scheduler的调度机制主要分两个阶段:
1. 过滤(Filter): 遍历所有节点，筛选出不满足 Pod 运行条件的节点。例如，如果一个节点的 CPU 或内存不足以满足 Pod 的请求（request），那么这个节点就会被过滤掉。
2. 打分(Score): 为所有通过过滤阶段的节点进行打分。每个评分插件都会对节点打一个分数，最后调度器会综合所有插件的分数，选择得分最高的节点来运行 Pod。


##  打分插件

```go
// nodeResourceStrategyTypeMap maps strategy to scorer implementation
var nodeResourceStrategyTypeMap = map[config.ScoringStrategyType]scorer{
	config.LeastAllocated: func(args *config.NodeResourcesFitArgs) *resourceAllocationScorer {
		resources := args.ScoringStrategy.Resources
		return &resourceAllocationScorer{
			Name:      string(config.LeastAllocated),
			scorer:    leastResourceScorer(resources),
			resources: resources,
		}
	},
	config.MostAllocated: func(args *config.NodeResourcesFitArgs) *resourceAllocationScorer {
		resources := args.ScoringStrategy.Resources
		return &resourceAllocationScorer{
			Name:      string(config.MostAllocated),
			scorer:    mostResourceScorer(resources),
			resources: resources,
		}
	},
	config.RequestedToCapacityRatio: func(args *config.NodeResourcesFitArgs) *resourceAllocationScorer {
		resources := args.ScoringStrategy.Resources
		return &resourceAllocationScorer{
			Name:      string(config.RequestedToCapacityRatio),
			scorer:    requestedToCapacityRatioScorer(resources, args.ScoringStrategy.RequestedToCapacityRatio.Shape),
			resources: resources,
		}
	},
}
```


这里的map会赋值给下面的判断逻辑

```go

// NewFit initializes a new plugin and returns it.
func NewFit(_ context.Context, plArgs runtime.Object, h framework.Handle, fts feature.Features) (framework.Plugin, error) {
    ...
	strategy := args.ScoringStrategy.Type
	scorePlugin, exists := nodeResourceStrategyTypeMap[strategy]
    ...

	return &Fit{
		ignoredResources:                sets.New(args.IgnoredResources...),
		ignoredResourceGroups:           sets.New(args.IgnoredResourceGroups...),
		enableInPlacePodVerticalScaling: fts.EnableInPlacePodVerticalScaling,
		enableSidecarContainers:         fts.EnableSidecarContainers,
		enableSchedulingQueueHint:       fts.EnableSchedulingQueueHint,
		handle:                          h,
		enablePodLevelResources:         fts.EnablePodLevelResources,
		resourceAllocationScorer:        *scorePlugin(args),
	}, nil
}
```

下面分别介绍打分插件



###  leastResourceScorer

```go

// leastResourceScorer favors nodes with fewer requested resources.
// It calculates the percentage of memory, CPU and other resources requested by pods scheduled on the node, and
// prioritizes based on the minimum of the average of the fraction of requested to capacity.
//
// Details:
// (cpu((capacity-requested)*MaxNodeScore*cpuWeight/capacity) + memory((capacity-requested)*MaxNodeScore*memoryWeight/capacity) + ...)/weightSum
func leastResourceScorer(resources []config.ResourceSpec) func([]int64, []int64) int64 {
	return func(requested, allocable []int64) int64 {
		var nodeScore, weightSum int64
		for i := range requested {
			if allocable[i] == 0 {
				continue
			}
			weight := resources[i].Weight
			resourceScore := leastRequestedScore(requested[i], allocable[i])
			nodeScore += resourceScore * weight
			weightSum += weight
		}
		if weightSum == 0 {
			return 0
		}
		return nodeScore / weightSum
	}
}

// The unused capacity is calculated on a scale of 0-MaxNodeScore
// 0 being the lowest priority and `MaxNodeScore` being the highest.
// The more unused resources the higher the score is.
func leastRequestedScore(requested, capacity int64) int64 {
	if capacity == 0 {
		return 0
	}
	if requested > capacity {
		return 0
	}

	return ((capacity - requested) * framework.MaxNodeScore) / capacity
}
```
这里的代码大致介绍了该插件的打分机制，`leastRequestedScore` 函数负责计算每一个资源的具体分数
这里的逻辑就是当前容量在减去请求量之后所占用的当前容量比例
在计算了某一个单项分数之后，再回到 `leastResourceScorer`,这个函数将会给每一个单项分数与权值相乘，最终计算总体的分数


总结: 该策略最终得出来的即为**分配的节点资源占当前node的比例越低分数越高，也就是越容易被调度**, 该策略可能更倾向于均匀分配每个节点资源

### mostResourceScorer
略过权值的计算

```go
func mostRequestedScore(requested, capacity int64) int64 {
	if capacity == 0 {
		return 0
	}
	if requested > capacity {
		// `requested` might be greater than `capacity` because pods with no
		// requests get minimum values.
		requested = capacity
	}

	return (requested * framework.MaxNodeScore) / capacity
}
```

总结: 该策略为**请求所占资源与当前节点容量占比越大分数越高**



### requestedToCapacityRatioScorer
```go

const maxUtilization = 100

// buildRequestedToCapacityRatioScorerFunction allows users to apply bin packing
// on core resources like CPU, Memory as well as extended resources like accelerators.
func buildRequestedToCapacityRatioScorerFunction(scoringFunctionShape helper.FunctionShape, resources []config.ResourceSpec) func([]int64, []int64) int64 {
	rawScoringFunction := helper.BuildBrokenLinearFunction(scoringFunctionShape)
	resourceScoringFunction := func(requested, capacity int64) int64 {
		if capacity == 0 || requested > capacity {
			return rawScoringFunction(maxUtilization)
		}

		return rawScoringFunction(requested * maxUtilization / capacity)
	}
	return func(requested, allocable []int64) int64 {
		var nodeScore, weightSum int64
		for i := range requested {
			if allocable[i] == 0 {
				continue
			}
			weight := resources[i].Weight
			resourceScore := resourceScoringFunction(requested[i], allocable[i])
			if resourceScore > 0 {
				nodeScore += resourceScore * weight
				weightSum += weight
			}
		}
		if weightSum == 0 {
			return 0
		}
		return int64(math.Round(float64(nodeScore) / float64(weightSum)))
	}
}

func requestedToCapacityRatioScorer(resources []config.ResourceSpec, shape []config.UtilizationShapePoint) func([]int64, []int64) int64 {
	shapes := make([]helper.FunctionShapePoint, 0, len(shape))
	for _, point := range shape {
		shapes = append(shapes, helper.FunctionShapePoint{
			Utilization: int64(point.Utilization),
			// MaxCustomPriorityScore may diverge from the max score used in the scheduler and defined by MaxNodeScore,
			// therefore we need to scale the score returned by requested to capacity ratio to the score range
			// used by the scheduler.
			Score: int64(point.Score) * (framework.MaxNodeScore / config.MaxCustomPriorityScore),
		})
	}

	return buildRequestedToCapacityRatioScorerFunction(shapes, resources)
}
```


# 资源获取信息
由上面代码可知，在分数的计算过程当中利用到了 `allocable`这个数组里面所统计的资源信息
而上面的插件加载和打分的函数位于`framework/plugins/noderesources/fit.go`当中
```go
// Score invoked at the Score extension point.
func (f *Fit) Score(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeName string) (int64, *framework.Status) {
	nodeInfo, err := f.handle.SnapshotSharedLister().NodeInfos().Get(nodeName) //获取nodeinfo,将使用nodeinfo内部的信息来决策调度
	if err != nil {
		return 0, framework.AsStatus(fmt.Errorf("getting node %q from Snapshot: %w", nodeName, err))
	}

	s, err := getPreScoreState(state)
	if err != nil {
		s = &preScoreState{
			podRequests: f.calculatePodResourceRequestList(pod, f.resources),
		}
	}

	return f.score(ctx, pod, nodeInfo, s.podRequests)
}
```
下面的f.score将会层层调用
```go

// score will use `scorer` function to calculate the score.
func (r *resourceAllocationScorer) score(
	ctx context.Context,
	pod *v1.Pod,
	nodeInfo *framework.NodeInfo,
	podRequests []int64) (int64, *framework.Status) {
	logger := klog.FromContext(ctx)
	node := nodeInfo.Node()

	// resources not set, nothing scheduled,
	if len(r.resources) == 0 {
		return 0, framework.NewStatus(framework.Error, "resources not found")
	}

	requested := make([]int64, len(r.resources))
	allocatable := make([]int64, len(r.resources))
	for i := range r.resources {
		alloc, req := r.calculateResourceAllocatableRequest(logger, nodeInfo, v1.ResourceName(r.resources[i].Name), podRequests[i])
		// Only fill the extended resource entry when it's non-zero.
		if alloc == 0 {
			continue
		}
		allocatable[i] = alloc
		requested[i] = req
	}

	score := r.scorer(requested, allocatable)

	if loggerV := logger.V(10); loggerV.Enabled() { // Serializing these maps is costly.
		loggerV.Info("Listed internal info for allocatable resources, requested resources and score", "pod",
			klog.KObj(pod), "node", klog.KObj(node), "resourceAllocationScorer", r.Name,
			"allocatableResource", allocatable, "requestedResource", requested, "resourceScore", score,
		)
	}

	return score, nil
}
```

这部分代码将会从传递的nodeinfo来获取allocatable数组和request
nodeinfo是从当前集群状态的'snapshot'中通过节点名称直接查询nodeinfo对象
而该snapshot则是不断从apiserver获取信息来进行更新，这一部分则是通过kubelet进行信息传递

在kubelet中，获取信息的函数主要来源于`pkg/kubelet/kubelet_node_status.go`

```go

// defaultNodeStatusFuncs is a factory that generates the default set of
// setNodeStatus funcs
func (kl *Kubelet) defaultNodeStatusFuncs() []func(context.Context, *v1.Node) error {
	// if cloud is not nil, we expect the cloud resource sync manager to exist
	var nodeAddressesFunc func() ([]v1.NodeAddress, error)
	if kl.cloud != nil {
		nodeAddressesFunc = kl.cloudResourceSyncManager.NodeAddresses
	}
	var setters []func(ctx context.Context, n *v1.Node) error
	setters = append(setters,
		nodestatus.NodeAddress(kl.nodeIPs, kl.nodeIPValidator, kl.hostname, kl.hostnameOverridden, kl.externalCloudProvider, kl.cloud, nodeAddressesFunc, utilnet.ResolveBindAddress),
		nodestatus.MachineInfo(string(kl.nodeName), kl.maxPods, kl.podsPerCore, kl.GetCachedMachineInfo, kl.containerManager.GetCapacity,
			kl.containerManager.GetDevicePluginResourceCapacity, kl.containerManager.GetNodeAllocatableReservation, kl.recordEvent, kl.supportLocalStorageCapacityIsolation()),
		nodestatus.VersionInfo(kl.cadvisor.VersionInfo, kl.containerRuntime.Type, kl.containerRuntime.Version),
		nodestatus.DaemonEndpoints(kl.daemonEndpoints),
		nodestatus.Images(kl.nodeStatusMaxImages, kl.imageManager.GetImageList),
		nodestatus.GoRuntime(),
		nodestatus.RuntimeHandlers(kl.runtimeState.runtimeHandlers),
		nodestatus.NodeFeatures(kl.runtimeState.runtimeFeatures),
	)

	setters = append(setters,
		nodestatus.MemoryPressureCondition(kl.clock.Now, kl.evictionManager.IsUnderMemoryPressure, kl.recordNodeStatusEvent),
		nodestatus.DiskPressureCondition(kl.clock.Now, kl.evictionManager.IsUnderDiskPressure, kl.recordNodeStatusEvent),
		nodestatus.PIDPressureCondition(kl.clock.Now, kl.evictionManager.IsUnderPIDPressure, kl.recordNodeStatusEvent),
		nodestatus.ReadyCondition(kl.clock.Now, kl.runtimeState.runtimeErrors, kl.runtimeState.networkErrors, kl.runtimeState.storageErrors,
			kl.containerManager.Status, kl.shutdownManager.ShutdownStatus, kl.recordNodeStatusEvent, kl.supportLocalStorageCapacityIsolation()),
		nodestatus.VolumesInUse(kl.volumeManager.ReconcilerStatesHasBeenSynced, kl.volumeManager.GetVolumesInUse),
		// TODO(mtaufen): I decided not to move this setter for now, since all it does is send an event
		// and record state back to the Kubelet runtime object. In the future, I'd like to isolate
		// these side-effects by decoupling the decisions to send events and partial status recording
		// from the Node setters.
		kl.recordNodeSchedulableEvent,
	)
	return setters
}
```

## MachineInfo

1. 获取原始机器信息（通过 machineInfoFunc，即 cAdvisor）。
2. 获取 Kubelet 自身计算的容量（通过 capacityFunc，主要用于临时存储）。
3. 获取设备插件报告的资源（通过 devicePluginResourceCapacityFunc）。
4. 获取节点预留资源（通过 nodeAllocatableReservationFunc）。
5. 计算 `node.Status.Capacity`：将上述所有来源的容量信息汇总。
6. 计算 `node.Status.Allocatable`：从 Capacity 中减去预留资源，并考虑设备插件的可分配量和 Huge Pages 的影响。


## MemoryPressureCondition
同样是统计nodestatus的代码
```go
		nodestatus.MemoryPressureCondition(kl.clock.Now, kl.evictionManager.IsUnderMemoryPressure, kl.recordNodeStatusEvent),
        ...
// MemoryPressureCondition returns a Setter that updates the v1.NodeMemoryPressure condition on the node.
func MemoryPressureCondition(nowFunc func() time.Time, // typically Kubelet.clock.Now
	pressureFunc func() bool, // typically Kubelet.evictionManager.IsUnderMemoryPressure
	recordEventFunc func(eventType, event string), // typically Kubelet.recordNodeStatusEvent
) Setter {
	return func(ctx context.Context, node *v1.Node) error {
		currentTime := metav1.NewTime(nowFunc())
		var condition *v1.NodeCondition

		// Check if NodeMemoryPressure condition already exists and if it does, just pick it up for update.
		for i := range node.Status.Conditions {
			if node.Status.Conditions[i].Type == v1.NodeMemoryPressure {
				condition = &node.Status.Conditions[i]
			}
		}

		newCondition := false
		// If the NodeMemoryPressure condition doesn't exist, create one
		if condition == nil {
			condition = &v1.NodeCondition{
				Type:   v1.NodeMemoryPressure,
				Status: v1.ConditionUnknown,
			}
			// cannot be appended to node.Status.Conditions here because it gets
			// copied to the slice. So if we append to the slice here none of the
			// updates we make below are reflected in the slice.
			newCondition = true
		}

		// Update the heartbeat time
		condition.LastHeartbeatTime = currentTime

		// Note: The conditions below take care of the case when a new NodeMemoryPressure condition is
		// created and as well as the case when the condition already exists. When a new condition
		// is created its status is set to v1.ConditionUnknown which matches either
		// condition.Status != v1.ConditionTrue or
		// condition.Status != v1.ConditionFalse in the conditions below depending on whether
		// the kubelet is under memory pressure or not.
		if pressureFunc() {
			if condition.Status != v1.ConditionTrue {
				condition.Status = v1.ConditionTrue
				condition.Reason = "KubeletHasInsufficientMemory"
				condition.Message = "kubelet has insufficient memory available"
				condition.LastTransitionTime = currentTime
				recordEventFunc(v1.EventTypeNormal, "NodeHasInsufficientMemory")
			}
		} else if condition.Status != v1.ConditionFalse {
			condition.Status = v1.ConditionFalse
			condition.Reason = "KubeletHasSufficientMemory"
			condition.Message = "kubelet has sufficient memory available"
			condition.LastTransitionTime = currentTime
			recordEventFunc(v1.EventTypeNormal, "NodeHasSufficientMemory")
		}

		if newCondition {
			node.Status.Conditions = append(node.Status.Conditions, *condition)
		}
		return nil
	}
}
```

这里的压力值主要会被evictionManager检测,可以看到pressureFunc()是一个方法参数，这个参数由setter传递`kl.evictionManager.IsUnderMemoryPressure()`
其位于 `pkg/kubelet/eviction/eviction_manager.go` 

```go

// IsUnderMemoryPressure returns true if the node is under memory pressure.
func (m *managerImpl) IsUnderMemoryPressure() bool {
	m.RLock()
	defer m.RUnlock()
	return hasNodeCondition(m.nodeConditions, v1.NodeMemoryPressure)
}
```
而这里仅仅是返回了标识符，该标识符的赋值则是通过`eviction_manager.go`的循环机制

该循环机制位于`synchornize()`函数中，其会调用`thersholdsMet()`函数来裁决是否触发了驱逐限制,然后继续`synchornize()`函数进行具体的flag赋值

```go

func (m *managerImpl) synchronize(diskInfoProvider DiskInfoProvider, podFunc ActivePodsFunc) ([]*v1.Pod, error) {
	ctx := context.Background()
	// if we have nothing to do, just return
    ...
	summary, err := m.summaryProvider.Get(ctx, updateStats)
    ...
	observations, statsFunc := makeSignalObservations(summary)    //observations 主要是来自于node信息， statsFunc来自Pod
    ...
	thresholds = thresholdsMet(thresholds, observations, false)     //返回驱逐名单
    ...

	if m.localStorageCapacityIsolation {                        //通过statsFunc来判断驱逐的Pod
		if evictedPods := m.localStorageEviction(activePods, statsFunc); len(evictedPods) > 0 {
			return evictedPods, nil
		}
	}
    ...
}
```





