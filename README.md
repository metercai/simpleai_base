# SimpleAI Base package
# Announce
I suddenly received a message forwarded to me by a friend. simpleai_base was reported as having security risks. So it is necessary to issue a statement here: 
- <b>simpleai_base has been open source since its birth, with every step of evolution, including minor code changes during development and debugging, recorded on Git. Binary code is also automatically compiled through actions on GitHub. Adhering to a completely transparent security policy, it can withstand any questioning and verification.
- The DID in simpleai_base is precisely a secure infrastructure that builds a trusted UID system through self certification and external certification to facilitate the establishment of subsequent P2P sharing mechanisms, bypass AI's dependence on large institutions and platforms, and ensure the rightful autonomy of each individual.
- We are willing to accept any supervision and friendly suggestions, continuously improve, and adhere to the bottom line of open source in innovative practices. </b>

# 声明
很突然的收到朋友转发给我的信息，simpleai_base被举报，认为simpleai_base有安全风险。所以有必要在此发布声明：
- <b>simpleai_base从一开始就是开源的，每一步的演变，包括开发调试过程的微小代码变更都记录在git上面，二进制代码也是在github上通过action自动编译的。遵循了完全透明的安全策略，可以经得起任何质询和检验。
- simpleai_base中的DID恰恰是一个安全基础设施，通过自证和他证构建可信任的UID系统，以促进后续P2P共享机制的建立，绕开AI对大机构和大平台的依赖，确保每个个体的应有自主权。
- 我们愿意接受任何监督和友好建议，持续改进，在创新实践中坚守开源的底线。</b>

# Plan / 计划
## DID ([Decentralized Identifier](https://en.wikipedia.org/wiki/Decentralized_identifiers))
- The DID in simpleai_base is a UID with a self verification mechanism, generated from SystemInfo. And upstream third-party nodes authenticate and record. This DID can be self verified and verified by others, thus establishing a trustworthy UID system that facilitates the establishment of subsequent sharing mechanisms. If there is no third-party verification, it can only be used locally through QR code and cannot participate in the sharing program.
- simpleai_base中的DID是一个具有自我验证机制的UID，由SystemInfo生成。上游第三方节点进行身份验证和备份记录。该DID既可以自我验证也可以被他人验证，从而建立一个值得信赖的UID系统，促进后续共享机制的建立。如果没有第三方验证，则只能通过二维码在本地使用，不能参与共享计划。
  
## libp2p ([the peer-to-peer network stack](https://libp2p.io/))
> libp2p is an open source networking library used by the world's most important distributed systems such as Ethereum, IPFS, Filecoin, Optimism and countless others. There are native implementations in Go, Rust, Javascript, C++, Nim, Java/Kotlin, Python, .Net, Swift and Zig. It is the simplest solution for global scale peer-to-peer networking and includes support for pub-sub message passing, distributed hash tables, NAT hole punching and browser-to-browser direct communication.
- We plan to use [rust-libp2p](https://github.com/libp2p/rust-libp2p) as a communication channel across private networks to ensure that the sharing mechanism is applicable to a wider range of network conditions.
- 我们计划使用[rust-libp2p](https://github.com/libp2p/rust-libp2p)作为跨私有网络的通信信道，以确保共享机制适用于更广泛的网络环境。

## DID + libp2p
- Under the collaboration of DID and libP2P, a sharing mechanism that is both autonomous, controllable, and trustworthy will be achieved.
- 在DID和libP2P的协作下，将实现一种自治、可控和可信的共享机制。
<img width="400" src="https://github.com/user-attachments/assets/0af243cc-fa3f-46a1-a496-220c6624da6c" />
<img width="400" src="https://github.com/user-attachments/assets/48a0a1e6-2076-4331-a8e9-99141a8228eb" />

# Advice & Contact
- We adhere to open source, make our code transparent, accept any supervision and friendly suggestions, and continuously improve. Contact me: 925457@qq.com
- 我们坚持开源，让代码透明，接受任何监督和友好建议，持续改进。联系我：925457@qq.com
