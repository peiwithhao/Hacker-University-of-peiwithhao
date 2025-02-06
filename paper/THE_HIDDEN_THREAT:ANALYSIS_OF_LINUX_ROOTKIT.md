# The Hidden Threat: Analysis of Linux Rootkit Techniques and Limitations of Current Detection Tools

该论文主要是介绍了几种rootkit手法和其检测工具



下面针对Linux上rootkit所存在的主要两个区域来进行分析
# 用户空间
指仅仅在ring3领域活动的rootkit
## 应用程序级别rootkit
此类rootkit是指修改单个应用程序的内容，例如修改`ls,ps`等二进制程序的输出来伪造向用户传递的信息，
但由于此类rootkit仅对单一某个程序,
且十分难以通过完整性检查，从而导致这一类rootkit日益减少

## 
