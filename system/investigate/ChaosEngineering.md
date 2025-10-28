# 混沌工程/故障注入工具调研
## 1. Choas Monkey

Chaos Monkey 是由 Netflix 开发的混沌工程工具，主要用于在生产环境中自动和随机地终止虚拟机实例，以测试系统的弹性和容错能力。其核心思想是通过制造不可预期的故障，确保系统能够自动恢复并保持高可用性。
当前版本的 Chaos Monkey 已完全集成到 Spinnaker 中，这是 Netflix 使用的持续交付平台。
Spinnaker是一个由 Netflix 创建并开源的、功能强大的多云持续交付（Continuous Delivery）平台,负责将软件从代码仓库安全、快速、可靠地发布到生产
  环境中。

### 工作原理

支持三类注入:
1. app:Chaos Monkey 每天将终止每个应用程序最多一个实例，无论这些实例如何组织成集群。
2. stack:Chaos Monkey 每天将终止每个堆栈最多一个实例。例如，如果某个应用定义了三个堆栈，那么 Chaos Monkey 每天最多会终止该应用中的三个实例。
3. cluster:Chaos Monkey 将每天终止每个集群最多一个实例。


Chaos Monkey 通过以下步骤进行工作：
1. 选择目标实例：Chaos Monkey 随机选择一个或多个虚拟机实例（或容器）作为目标, 这些目标是通过预配置的构建池(配置组)中获得
2. 停止实例：它会通过Spinnaker平台立即停止目标实例，模拟硬件故障、实例宕机或其他系统故障。
3. 监控系统反应：Chaos Monkey 会观察系统如何应对实例停止的情况，并记录系统的反应。
4. 验证恢复能力：系统的自我修复能力、故障转移机制、容错能力等将被检验。如果系统能够恢复并保持正常运行，Chaos Monkey 认为实验成功；否则，团队会根据结果进行问题分析和修复。

### 工作目标
Chaos Monkey 旨在通过以下几个方面帮助企业和开发团队提高系统的可靠性：

1. 增强系统韧性：模拟真实故障，帮助团队发现和解决潜在的系统弱点。特别是在生产环境中，分布式系统由于多个组件和服务的相互依赖，容易受到故障的影响，Chaos Monkey 通过频繁的故障注入测试系统的强健性。
2. 验证容错机制：确保系统的容错机制有效，服务能够在出现单点故障时自动恢复，减少系统中断的时间和影响。
3. 降低故障恢复时间：通过反复模拟故障情况，团队能够提前发现系统的恢复瓶颈，减少系统在故障情况下的恢复时间。
4. 提高运维团队的应急响应能力：让团队成员在面对故障时能够更熟练地处理和恢复系统，提升团队的应急响应能力

### 工作流程

Chaos Monkey 的工作流程可以分为以下几个阶段：

1. 定义目标和范围：在使用 Chaos Monkey 之前，团队需要定义实验的目标，明确实验的范围和要解决的具体问题。例如，团队可能希望验证服务的高可用性，或者测试某个特定依赖项的恢复能力。
2. 选择故障注入类型：Chaos Monkey 仅仅注入单种类型的故障,即实例宕机（即模拟服务器的崩溃或停止运行）
3. 执行实验并监控：启动实验后，Chaos Monkey 会在系统中随机选择目标实例并执行故障注入。工程师需要监控系统反应，观察是否发生了预期的故障，并记录相关数据。
4. 分析结果和优化：实验结束后，团队需要分析系统的表现，找出可能的弱点和瓶颈，并进行相应的优化。这一过程可以帮助团队持续改进系统架构，增强其容错性和可靠性。

### 应用场景

- 验证系统的高可用性和自愈能力。
- 检查服务在部分节点失效时的表现。
- 发现系统潜在的单点故障和恢复流程中的问题。

### 安全与权限

- 通过访问控制和配置文件限制可操作的服务和实例，避免误操作。
- 支持与 CI/CD 流程集成，实现自动化混沌测试。

## 2. Choas Toolkit

### 工作目标

由两个简单的微服务组成，通过HTTPS相互通信

### 工作流程
![ctk flow](./img/ctk.flow.svg) 

它的核心功能是帮助编写和执行混沌工程实验，以测试系统在面对混乱和预期外故障时的弹性和恢复能力
  。它旨在让所有工程师都能实践混沌工程。

  其工作方式是通过一个声明式的实验文件（通常是 JSON 或 YAML 格式），您可以在其中定义：
      1. 稳态假设（Steady-State Hypothesis）: 系统的正常状态是怎样的。
      2. 探测（Probes）: 在实验之前、之中和之后运行，用于验证系统是否处于稳态。
      3. 行动（Actions）: 注入到系统中的具体故障或事件，例如关闭一个服务、增加网络延迟等。
      4. 回滚（Rollbacks）: 在实验结束后，用于撤销“行动”所做更改，使系统恢复原状的补偿操作。

具体的执行流程如下：

 1. 发现与验证 (Discovery & Validation)
       * 发现: 工具首先会查找并加载所有已安装的扩展（extensions），以了解当前环境所有可用的“行动”（Actions）和“探测”（Probes）。
       * 验证: 接着，它会读取并解析您的实验文件（JSON/YAML），检查其语法是否正确，并确认实验中声明要使用的所有“行动”和“探测”是否在已发现的扩展中都存在。如果语
         法错误或找不到对应的功能，流程会在此处失败并退出。

   2. 稳态假设检验 (Steady-State Hypothesis)
       * 工具会执行“稳态假设” (steady_state_hypothesis) 区块中定义的所有“探测”（Probes）。
       * 目的: 验证系统在实验开始前是否处于“健康”或“正常”的预期状态。
       * 如果任何一个探测失败，意味着系统在实验开始前就已经不正常了。默认情况下，实验会立即停止，以防止在不健康的系统上注入更多混乱。

   3. 执行方法 (Method)
       * 只有当稳态假设检验通过后，工具才会开始执行 method 区块。这是注入混沌的核心步骤。
       * method 区块包含一个或多个“行动”（Actions），它们会按顺序执行，对系统施加干扰（例如，关闭一台服务器）。
       * 在 method 区块中，您也可以穿插一些“探测”（Probes），用于在注入故障期间持续观察系统的状态。

   4. 再次检验稳态假设 (Post-Chaos Check)
       * 在 method 区块执行完毕后，工具会再一次执行“稳态假设” (steady_state_hypothesis) 区块中的所有探测。
       * 目的: 检验在经历了“行动”的干扰后，您的系统是否仍然保持（或恢复到）“健康”状态。
       * 实验结果: 如果此时所有探测都通过，意味着您的系统成功地抵御了这次混沌事件，实验被认为是成功的。如果任何一个探测失败，则证明系统未能保持稳定，实验失败。

   5. 执行回滚 (Rollbacks)
       * 无论实验成功与否，工具最后都会执行 rollbacks 区块中定义的操作。
       * 目的: 
         清理和撤销“行动”对系统所做的更改，使其恢复到实验开始前的状态（例如，重启之前被关闭的服务器）。这是一个“清理”步骤，旨在确保实验环境的可重复使用性。

### 设计思想

Chaos Toolkit 的工作流程体现了其深刻的设计思想，这些思想源于科学实验的方法论。

   1. 声明式与开放性 (Declarative & Open)
       * 实验是用简单的 JSON 或 YAML 文件声明的，而不是用复杂的代码编写。这使得非开发人员也能读懂、编写和审查实验，降低了混沌工程的门槛。
       * 它是一个开放的平台，不绑定任何特定的技术或云厂商。通过可插拔的扩展模型，它可以适应任何系统。

   2. 可验证与可证伪性 (Verifiable & Falsifiable)
       * 设计的核心是稳态假设。您不是在随机地破坏系统，而是在验证一个明确的假设：“即使我这样做，系统也应该保持正常”。
       * 通过在实验前后运行两次相同的探测，工具严格地验证了这个假设是否成立。这种方法让混沌工程从“破坏东西”变成了严谨的、可度量的科学实验。

   3. 安全与可控 (Safe & Controlled)
       * 事前检查: 如果系统在实验前就不稳定，实验不会运行。
       * 事后清理: rollbacks 机制确保实验环境可以被清理和恢复，最大限度地减少实验的意外影响。
       * 整个流程是透明且可预测的，用户清楚地知道每一步会发生什么。

### 所支持的故障类型

 chaostoolkit 本身是一个核心框架和实验运行器，其强大之处在于它的可扩展性。它本身不包含一个固定的 、内置的“故障类型”列表。 相反，具体的“故障类型”（即“行动”和“探测”）是通过驱动扩展（Driver Extensions）来提供的。您可以根据目标平台（如 Kubernetes, AWS, Azure,  或者本地进程）安装相应的扩展，从而获得在该平台上执行混沌实验的能力。

  这意味着它几乎可以支持任何类型的故障，只要能通过 Python 代码实现它。例如：

   * 应用层故障: 模拟应用崩溃、增加 CPU 或内存负载、引入延迟。
   * 网络层故障: 模拟网络中断、丢包、DNS 查询失败。
   * 基础设施层故障: 终止云主机实例 (VMs)、关闭容器 (Pods)、移除存储卷。
   * 平台层故障: 模拟 API 限流、认证失败。

## 3. LitmusChaos

### 基本介绍

石蕊是一组用于云原生混沌工程的工具。石蕊为运维人员提供了人工控制混沌的工具，用以在所部署的环境中找到软件设计的缺陷。运维人员可以使用石蕊在暂存区乃至生产环境里通过混沌实验来找出逻辑错误和软件漏洞。通过修复这些软件的缺陷，可以提升系统的整体抗打击能力。

石蕊以云原生的方法来创建，管理和监控混沌事件，通过以下的KubernetesCRD对象来实现对混沌事件的编排：

- **ChaosEngine**: 通过这个对象来关联一个Kubernnetes的应用或是Kubernetes节点。石蕊的Chaos-Operator会watch这个对象并触发混沌事件。
- **ChaosExperiment**: 这个对象包含了一组混沌事件的配置。当ChaoseEngine触发混沌事件的时候，operator就会创建ChaoseExpeiment对象。
- **ChaosResult**: 这个对象会保留混沌事件的结果。这个对象是ChaosEngine触发混沌事件时由operator创建的。

![litmus](./img/litmus.png)

### 注意事项

- 网络混沌测试目前不支持除Docker以外的容器运行时，如containerd和CRIO
- 石蕊混沌控制器以及混沌测试对象以Kubernetes资源的形式运行于Kubernetes集群中。在airgap环境需要在把镜像以及CR定义预先加载到机器上。
- 对于特定公有云平台(如AWS，GCP)，账号信息是通过Kubernetes secret的方式传入的。别的传入方式尚需进一步测试及实现。
- 一些混沌测试需要从pod里调用Docker API所以需要挂载Docker socket。需要自行判断是否要给开发者/运维权限来运行这些测试。
- 在一些(少数)情况下混沌测试需要privileged container权限

### 工作流

![./litmus.png](./img/litmuschaos.png)

故障执行在创建 ChaosEngine 资源时触发。ChaosEngine 资源与 Chaos Runner 交互，后者由 Chaos Operator  创建。Chaos Runner 创建故障作业来执行故障业务逻辑。通常，这些 ChaosEngine 嵌入在 Litmus  混沌实验的“步骤”中。但是，也可以手动创建和应用 Chaos Engine，然后由 Chaos Operator  协调此资源并触发故障执行。Chaos 故障分为以下几类：

- Kubernetes Faults
  - Pod-Level Chaos 
  - Node-Level Chaos 
- Application Chaos 
- Cloud Infrastructure 

#### 故障注入步骤

1. 混乱故障执行由故障作业触发
2. 获取故障可调参数和低级执行细节
3. ChaosResult 被初始化并且其判决被更新为“Awaited”以表明故障当前正在运行
4. 验证相应故障的稳态条件。如果发现条件无效，则停止故障执行，并将 ChaosResult 更新为“失败”
5. 一旦验证了稳态条件，就会创建故障资源以促进混沌注入
6. 对目标资源执行混沌注入，持续指定的混沌持续时间
7. 混沌注入被恢复
8. 进行混沌后状态检查以确保稳定状态仍然保持
9. 如果检查无效，ChaosEngine 和 ChaosResult 判定将更新为“失败”，否则将更新为“通过”
10. Fault execution ends. 故障执行结束

## 4. ChaosBlade
### 基本介绍

ChaosBlade 是阿里巴巴开源的一款遵循混沌工程原理和混沌实验模型的实验注入工具，帮助企业提升分布式系统的容错能力，并且在企业上云或往云原生系统迁移过程中业务连续性保障。
Chaosblade 是内部 MonkeyKing 对外开源的项目，其建立在阿里巴巴近十年故障测试和演练实践基础上，结合了集团各业务的最佳创意和实践。


ChaosBlade支持丰富的实验场景，场景包括：
+ 基础资源：比如 CPU、内存、网络、磁盘、进程等实验场景；
+ Java 应用：比如数据库、缓存、消息、JVM 本身、微服务等，还可以指定任意类方法注入各种复杂的实验场景；
+ C++ 应用：比如指定任意方法或某行代码注入延迟、变量和返回值篡改等实验场景；
+ Docker 容器：比如杀容器、容器内 CPU、内存、网络、磁盘、进程等实验场景；
+ 云原生平台：比如 Kubernetes 平台节点上 CPU、内存、网络、磁盘、进程实验场景，Pod 网络和 Pod 本身实验场景如杀 Pod，容器的实验场景如上述的 Docker 容器实验场景；


### 相关工具
![chaosblade](./img/chaos_blade.png)
将场景按领域实现封装成一个个单独的项目，不仅可以使领域内场景标准化实现，而且非常方便场景水平和垂直扩展，通过遵循混沌实验模型，实现 chaosblade cli 统一调用。目前包含的项目如下：
+ chaosblade：混沌实验管理工具，包含创建实验、销毁实验、查询实验、实验环境准备、实验环境撤销等命令，是混沌实验的执行工具，执行方式包含 CLI 和 HTTP 两种。提供完善的命令、实验场景、场景参数说明，操作简洁清晰。
+ chaosblade-spec-go: 混沌实验模型 Golang 语言定义，便于使用 Golang 语言实现的场景都基于此规范便捷实现。
+ chaosblade-exec-os: 基础资源实验场景实现。
+ chaosblade-exec-docker: Docker 容器实验场景实现，通过调用 Docker API 标准化实现。
+ chaosblade-exec-cri: 容器实验场景实现，通过调用 CRI 标准化实现。
+ chaosblade-operator: Kubernetes 平台实验场景实现，将混沌实验通过 Kubernetes 标准的 CRD 方式定义，很方便的使用 Kubernetes 资源操作的方式来创建、更新、删除实验场景，包括使用 kubectl、client-go 等方式执行，而且还可以使用上述的 chaosblade cli 工具执行。
+ chaosblade-exec-jvm: Java 应用实验场景实现，使用 Java Agent 技术动态挂载，无需任何接入，零成本使用，而且支持卸载，完全回收 Agent 创建的各种资源。
+ chaosblade-exec-cplus: C++ 应用实验场景实现，使用 GDB 技术实现方法、代码行级别的实验场景注入。

### 云原生
chaosblade-operator 项目是针对云原生平台所实现的混沌实验注入工具，遵循混沌实验模型规范化实验场景，把实验定义为 Kubernetes CRD 资源，将实验模型映射为 Kubernetes 资源属性，很友好地将混沌实验模型与 Kubernetes 声明式设计结合在一起，在依靠混沌实验模型便捷开发场景的同时，又可以很好的结合 Kubernetes 设计理念，通过 kubectl 或者编写代码直接调用 Kubernetes API 来创建、更新、删除混沌实验，而且资源状态可以非常清晰地表示实验的执行状态，标准化实现 Kubernetes 故障注入。除了使用上述方式执行实验外，还可以使用 chaosblade cli 方式非常方便的执行 kubernetes 实验场景，查询实验状态等
![cloudnative](./img/chaosblade_cloudnative.png)

## 5. Chaos Mesh
Chaos Mesh 是一个开源的云原生混沌工程平台，提供丰富的故障模拟类型，具有强大的故障场景编排能力，
方便用户在开发测试中以及生产环境中模拟现实世界中可能出现的各类异常，帮助用户发现系统潜在的问题。Chaos Mesh 提供完善的可视化操作，旨在降低用户进行混沌工程的门槛。用户可以方便地在 Web UI 界面上设计自己的混沌场景，以及监控混沌实验的运行状态。

### 架构概览
Chaos Mesh 基于 Kubernetes CRD (Custom Resource Definition) 构建，根据不同的故障类型定义多个 CRD 类型，并为不同的 CRD 对象实现单独的 Controller 以管理不同的混沌实验。Chaos Mesh 主要包含以下三个组件:

+ Choas Dashboard: 可视化组件
+ Choas Controller Manager: 负责混沌实验的调度与管理，包含多个CRD Controller
+ Chaos Daemon: Chaos Mesh的主要执行组件，以DaemonSet的方式运行，默认拥有特权，该组件主要通过侵入目标Pod Namespace的方式干扰具体网络设备、文件系统、内核等

![chaos mesh architecture](./img/architecture-chaos-mesh.png)

### 基本功能
#### 故障注入
在kubernetes上有以下几类故障场景：
分为基础资源类型故障、平台类型故障、应用层故障
+ 基础资源故障: 
    + PodChaos：模拟 Pod 故障，例如 Pod 节点重启、Pod 持续不可用，以及特定 Pod 中的某些容器故障。
    + NetworkChaos：模拟网络故障，例如网络延迟、网络丢包、包乱序、各类网络分区。
    + DNSChaos：模拟 DNS 故障，例如 DNS 域名解析失败、返回错误 IP 地址。
    + HTTPChaos：模拟 HTTP 通信故障，例如 HTTP 通信延迟。
    + StressChaos：模拟 CPU 抢占或内存抢占场景。
    + IOChaos：模拟具体某个应用的文件 I/O 故障，例如 I/O 延迟、读写失败。
    + TimeChaos：模拟时间跳动异常。
    + KernelChaos：模拟内核故障，例如应用内存分配异常。(调用bpfki)
+ 平台类型故障：
    + AWSChaos：模拟 AWS 平台故障，例如 AWS 节点重启。
    + GCPChaos：模拟 GCP 平台故障，例如 GCP 节点重启。
+ 应用层故障：
    + JVMChaos：模拟 JVM 应用故障，例如函数调用延迟。

除此之外ChaosMesh还提供物理节点的故障注入：

+ 进程：对进程进行故障注入，支持进程的 kill、stop 等操作。
+ 网络：对物理机的网络进行故障注入，支持增加网络延迟、丢包、损坏包等操作。
+ 压力：对物理机的 CPU 或内存注入压力。（使用stress-ng创造压力）
+ 磁盘：对物理机的磁盘进行故障注入，支持增加读写磁盘负载、填充磁盘等操作。
+ 主机：对物理机本身进行故障注入，支持关机等操作。



#### 混沌实验场景
用户运行混沌场景，可以通过一系列的混沌实验，不断地扩大爆炸半径（包括攻击范围）和增加故障类型。运行混沌实验后，用户可以方便地检查当前的应用状态，判断是否需要进行后续混沌实验。同时用户可以不断地迭代混沌实验场景，积累混沌实验场景，以及方便地将已有的混沌实验场景复用到其他应用混沌实验中，大大降低了混沌实验的成本。


目前混沌实验场景提供的功能有：
+ 编排串行混沌实验
+ 编排并行混沌实验
+ 支持状态检查步骤
+ 支持中途暂停混沌实验
+ 支持使用 YAML 文件定义和管理混沌实验场景
+ 支持通过 Web UI 定义和管理混沌实验场景

#### 可视化操作
用户可以直接通过可视化界面来管理和监控混沌实验
![dashboard chaos mesh](./img/dashbord-chaos_mesh.png)
#### 安全保障
Chaos Mesh 通过 Kubernetes 原生的 RBAC（基于角色的权限控制）功能对权限进行管理。
用户可以根据实际的权限需求自由地创建多种 Role，然后绑定到用户名 Service Account 上，最后生成 Service Account 对应的 Token。用户使用该 Token 登陆 Dashboard，只能在该 Service Account 允许的权限范围内进行 Chaos 实验。


# 参考
[https://github.com/chaos-mesh/chaosd?tab=readme-ov-file](https://github.com/chaos-mesh/chaosd?tab=readme-ov-file) 
[https://github.com/chaos-mesh/chaos-mesh/tree/master/controllers](https://github.com/chaos-mesh/chaos-mesh/tree/master/controllers)

[https://github.com/Netflix/chaosmonkey](https://github.com/Netflix/chaosmonkey)

[https://chaostoolkit.org/reference/tutorials/run-flow/](https://chaostoolkit.org/reference/tutorials/run-flow/)

[https://github.com/litmuschaos/litmus/blob/master/translations/README-chn.md](https://github.com/litmuschaos/litmus/blob/master/translations/README-chn.md)

[https://docs.litmuschaos.io/docs/introduction/features](https://docs.litmuschaos.io/docs/introduction/features)
