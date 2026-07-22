<!-- Threat Modeling Skill | Version 3.1.0 (20260313a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

## **Executive Summary**

Software engineering is currently undergoing a major paradigm shift—from waterfall development to agile iteration to AI-assisted programming. This transformation affects philosophy, processes, and technology alike. Security engineering must adapt accordingly, evolving from "document-driven, phase-separated" to "code-driven, verification-closed-loop," and from "gate-based, external tooling" to "extreme shift-left, rapid iteration."



---

## **Chapter 1: The Role of SDL and Security Processes in Traditional Software Lifecycles**

### **1.1 Theory and Practice of the Security Development Lifecycle (SDL)**

The traditional Security Development Lifecycle (SDL) embeds security into each phase of software development. This methodology originated from Microsoft's "Trustworthy Computing" initiative launched in 2002 in response to worms like Code Red and Nimda. The core insight was: **security must be built into products from the design phase, not remediated afterward**.

In the theoretical SDL model, each phase carries distinct security responsibilities:

**Requirements Analysis Phase**: Teams identify compliance requirements (e.g., data protection regulations, industry security standards) and define security features (e.g., identity and permission isolation, encryption algorithm strength, authentication mechanisms, audit logging). Since concrete system design is absent at this stage, security work remains at the level of principled declarations.

**Design Phase**: In SDL theory, this is the primary phase for Threat Modeling. Architects and security experts review system architecture diagrams, attempting to identify potential design flaws before coding begins. The STRIDE model developed by Microsoft is a key methodology for this phase.

**Implementation Phase**: Static Application Security Testing (SAST) and secure coding standards are introduced. Experienced developers apply secure design patterns following coding standards, IDEs use security plugins for real-time vulnerability pattern detection, and SAST tools perform periodic weakness scanning at designated checkpoints. However, these tools are essentially pattern matchers—they can capture specific dangerous patterns (e.g., unsafe use of `strcpy`), but struggle to assess actual risk in business process contexts, especially complex business logic vulnerabilities.

**Verification Phase**: Dynamic Application Security Testing (DAST), Interactive Application Security Testing (IAST), and manual penetration testing are executed at this stage. While these techniques can identify real issues, defects discovered when products near completion incur higher remediation costs. In practice, positional conflicts often create friction between development and security teams.

**Release and Response Phase**: Runtime monitoring, security incident response, and vulnerability patching. Issues discovered at this stage stem from insufficient threat coverage during the design phase, while remediation costs and derivative risks are significantly amplified.


### **1.2 Security Activity Insertion Points in Traditional Development Processes**

Understanding the design assumptions of traditional SDL requires analyzing the time distribution characteristics of traditional development processes:

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                    Time Distribution of Traditional Software Development             │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│   Requirements    Design        Implementation (Coding)    Verification (Testing) Release│
│   ├──────────┼─────────────┼───────────────────────┼─────────────────────────┼────┤ │
│   │   15%    │    20%      │         30%           │          30%            │ 5% │ │
│   │          │             │                       │                         │    │ │
│   │          │             │    ┌───────────────────────────────────┐        │    │ │
│   │          │             │    │    Primary Iteration Cycle        │        │    │ │
│   │          │             │    │    (Coding ↔ Testing)             │        │    │ │
│   │          │             │    │    ~60%+ of total development     │        │    │ │
│   │          │             │    └───────────────────────────────────┘        │    │ │
│   │          │             │                       │                         │    │ │
│   ├──────────┼─────────────┼───────────────────────┼─────────────────────────┼────┤ │
│   │          │  Threat     │      SAST/Code Review │  IAST/DAST/Pentest/     │    │ │
│   │          │  Modeling   │                       │  Security Testing       │    │ │
│   │          │  (Theory)   │                       │  (Actual insertion point)│   │ │
│   │          │             │                       │                         │    │ │
│   └──────────┴─────────────┴───────────────────────┴─────────────────────────┴────┘ │
│                                                                                      │
│   Key Observations:                                                                  │
│   ─────────────────────────────────────────────────────────────────────────────      │
│   • Threat modeling should theoretically occur during design, but due to limited     │
│     actionable information, it is often postponed to the testing phase               │
│   • The verification phase (testing) provides adequate time windows, becoming the    │
│     primary insertion point for security work                                        │
│   • Security testing, penetration testing, and compliance audits—high-investment     │
│     activities—are executed in this phase                                            │
│   • In traditional lifecycles, this "verification phase" time buffer is sufficient   │
│     to accommodate security activities                                               │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

Traditional SDL models, built on traditional software engineering methods, assume: **development processes have clear phase boundaries where security activities can be executed at specific stages**. The verification phase, with its longer duration and clear quality gate role, has become the primary insertion point for security work.


### **1.3 Overview of the STRIDE Threat Modeling Method**

STRIDE, commonly used in threat modeling, was proposed by Microsoft engineers Loren Kohnfelder and Praerit Garg in 1999. It encompasses six threat categories:

| Category | Full Name | Definition | Typical Defense Mechanisms |
|----------|-----------|------------|---------------------------|
| **S** | Spoofing | Impersonating another identity for unauthorized access | Authentication, digital signatures, multi-factor verification |
| **T** | Tampering | Unauthorized modification of data or code | Integrity checks, digital signatures, audit logs |
| **R** | Repudiation | Denying performed actions | Audit logs, timestamps, non-repudiation signatures |
| **I** | Information Disclosure | Exposing sensitive information to unauthorized parties | Encryption, access control, data masking |
| **D** | Denial of Service | Preventing legitimate users from accessing services | Rate limiting, redundancy design, failover |
| **E** | Elevation of Privilege | Gaining elevated privileges from a low-privilege identity | Least privilege principle, sandboxing, boundary validation |

STRIDE was designed to provide a **structured thinking framework** that helps non-security experts systematically examine potential threats in designs.

**Traditional STRIDE Practice Flow**:

1. **Data Flow Diagram (DFD) Creation**: Decompose the system into four element types—external entities, processes, data stores, and data flows—and annotate trust boundaries
2. **Element-by-Element Threat Enumeration**: For each element and interaction in the DFD, systematically pose questions according to the STRIDE model
3. **Mitigation Design**: Design corresponding security controls for identified threats


### **1.4 Gap Analysis: Theory vs. Practice**

STRIDE methodology guides and Microsoft's official documentation state that threat modeling is "most effective when performed during the design phase." However, industry observations reveal: **the theoretical model of design-phase threat modeling faces implementation barriers in most organizations**.

**Primary difficulties in implementing STRIDE**:

First, **the "design phase" has blurred boundaries in modern development**. In agile environments, design and implementation are highly intertwined. A module designed in Sprint 1 may be adjusted in Sprint 3 due to requirement changes, invalidating the original threat model.

Second, **effective STRIDE analysis requires specific design information**. Abstract architecture diagrams (e.g., "User → Load Balancer → Web Server → Database") cannot support meaningful threat analysis. Only with concrete implementation details (e.g., "JWT used for session management," "database stores plaintext passwords") can threat enumeration produce substantive conclusions. These details are typically determined during implementation.

Finally, **resource constraints** are a critical bottleneck (and create significant cost increases). Effective STRIDE analysis requires collaboration among architects, developers, and security experts. In fast-paced product development, convening threat modeling analysis and decision meetings for every design decision is impractical. Industry experience shows that fully implementing threat modeling can add 3-5% to overall software costs.

**Common Alternative Practice Patterns**:

Due to various constraints and issues inherent in traditional SDL and threat modeling, the industry often adopts simplified or alternative approaches:

- **Implementation-phase threat modeling**: Conducted during or after coding (testing phase) when more concrete system information is available; this is the most common actual scenario
- **Sprint-level incremental threat modeling**: In agile environments, threat modeling is decomposed into fixed activities within each sprint
- **Developer-driven lightweight checklists**: Simplified checklists based on STRIDE thinking for developers to self-check during code review
- **Threat modeling as code**: Using tools like pytm and threagile to define threat models as code


### **1.5 Limitations Analysis of Code Review**

Code review is another important gate security control in traditional SDL. If threat modeling is macro-level architecture audit, Code Review is micro-level implementation verification. In traditional SDL, code review occurs at the end of implementation or as a CI pipeline gate.

However, code review faces the following practical implementation limitations:

**Context limitations** are the primary obstacle. In microservice architectures, complete business flows may span multiple services involving numerous RPC calls. Reviewers face single-commit diffs (tens to hundreds of lines of code changes) and struggle to construct complete call chains spanning thousands of lines. An input validation function that appears complete may be ineffective if placed after the wrong trust boundary.

**Cognitive load** limits review depth. Research shows that code review effectiveness significantly decreases beyond 200-400 lines of code. Reviewers easily spot syntax errors or explicit injection vulnerabilities but struggle to detect architecture violations, race conditions, or business logic flaws.

| Dimension | Traditional STRIDE Threat Modeling | Traditional Code Review |
|-----------|-----------------------------------|------------------------|
| **Analysis Object** | Design documents, architecture diagrams, DFD | Code changes (Diff/PR) |
| **Theoretical Phase** | Design phase (early) | Development phase (mid-late) |
| **Actual Phase** | Often postponed or omitted | CI pipeline gate |
| **Core Limitation** | Abstraction-implementation gap, insufficient design info | Context missing, cognitive load |
| **Resource Dependency** | Experts with architecture + offensive/defensive skills | Individual developer security awareness |
| **Output Format** | Static documents, risk lists | Code comments, modification suggestions |
| **Verification Capability** | Weak (difficult to automate verification) | Medium (verifiable through testing, limited coverage) |

---

## **Chapter 2: Challenges of Traditional SDL Methods: Cognitive Bottlenecks and Validation Gaps**

### **2.1 Synchronization/Consistency Issues Between Documentation and Code**

Traditional STRIDE analysis starts from design documents or architecture diagrams. However, software iteration and development are dynamic evolutionary processes. Design documentation begins diverging from actual code at the start of coding (Implementation Drift). As engineering scale grows and code changes accumulate, synchronization gaps widen.

Typical example: A security team performs threat modeling in Q1 based on architect-provided design documents, identifying 15 high-risk threats. By Q3 product launch, technical debt, architecture adjustments, and requirement changes during development cause significant divergence between the actual system and original design. Version differences create "shadow areas" between manually predefined "threat models" and actual running system instances.

Some high-risk vulnerabilities arise precisely from design-implementation gaps. For example, design documentation specifies "all API calls must pass through authentication middleware," but actual implementation may contain debug endpoints that bypass authentication—issues often overlooked in static design document analysis.


### **2.2 Expert Resource Availability Constraints**

Effective STRIDE analysis requires both system architecture understanding and offensive/defensive practical experience. To assess API endpoint privilege escalation risks, analysts must understand:

- Web framework authentication middleware implementation mechanisms
- Common JWT token signature weaknesses (e.g., algorithm confusion attacks)
- RBAC/ABAC access control model implementation pitfalls
- Related historical vulnerabilities (e.g., CVE-2015-9235 JWT None algorithm vulnerability)

Experts combining "architecture vision + offensive/defensive depth" are scarce in the industry. Without qualified personnel and adequate time allocation, threat modeling and code audits often devolve into formalistic checklist filling.


### **2.3 Missing Verification Closed Loop**

Traditional STRIDE output is static threat lists and mitigation recommendations. After development teams apply fixes, how does the security team verify fix effectiveness?

Existing methods generally **lack low-cost, automatable verification mechanisms**. Threat modeling produces descriptive content ("SQL injection risk exists here") rather than executable test cases ("test this endpoint with `' OR 1=1 --` payload"). The broken identification-remediation-verification chain allows known risks to persist in systems long-term.


### **2.4 STRIDE's Dependence on Implementation Information**

Can STRIDE analysis produce meaningful conclusions without detailed layered design and code implementation?

Traditional static STRIDE analysis faces another issue: the disconnect between security design-assessment-control-verification. "This framework primarily conducts theoretical threat analysis during conceptual design phases, not during post-release security assessment phases." STRIDE's design assumes analysts possess sufficiently specific system information. When information is insufficient, analysis tends toward abstraction—one can say "the user authentication module may face spoofing threats" but cannot identify specific attack paths or vulnerability locations.


### **2.5 Hidden Dependencies on Process Insertion Points**

Traditional SDL and STRIDE methodologies have a latent assumption: **development processes have sufficiently long verification phases that provide time windows for security activities**.

In traditional development models:

- **Coding and testing are separated**: Developers write code, testing teams independently execute tests
- **Testing phase has adequate time**: Verification phase typically occupies 25-35% of project cycles
- **Security activities can be embedded in testing phase**: Penetration testing, security audits, and compliance checks are executed here

Under this model, even if threat modeling isn't completed during design, security teams still have opportunities to remediate during testing—executing security tests, discovering vulnerabilities, requesting fixes. **The testing phase becomes a "buffer zone" for security work**.

However, this assumption faces challenges under new development paradigms (see Chapter 3).

Traditional threat modeling faces timing dilemmas:

- **Too early**: Insufficient design information, analysis becomes abstract
- **Too late**: Higher remediation costs, missed early intervention opportunities
- **Continuous**: Lacks automation support, manual costs unsustainable


---

## **Chapter 3: Changes and Security Implications from AI-Assisted Programming: Structural Left-Shift of the Development Main Loop**

### **3.1 Programming Paradigm Changes and Main Loop Restructuring**

AI-assisted programming tools (GitHub Copilot, Claude Code, etc.) have transformed software development work patterns. These tools significantly reduce the marginal cost of code generation—developers shift from character-by-character coding to describing intent and reviewing AI-generated results. This role change brings substantial increases in development **speed** and code **volume** and **complexity**.

More profound impacts of increasingly powerful and intelligent AI-assisted programming tools on the software ecosystem include: **the development process main loop has undergone structural left-shift**.

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│          Structural Left-Shift of Development Main Loop: Traditional vs AI-Assisted  │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│  【Traditional Development Model】                                                   │
│  ─────────────────────────────────────────────────────────────────────────────────── │
│                                                                                      │
│   Requirements ──► Design ──────► Coding ◄───────────────────► Testing ──► Release  │
│     15%             20%           │                              │       5%         │
│                                   │        Main Loop (60%)       │                  │
│                                   │    ┌─────────────────────────┐│                 │
│                                   └───►│    Coding ↔ Testing     │◄┘                │
│                                        │  (Manual coding +       │                  │
│                                        │   independent testing)  │                  │
│                                        └─────────────────────────┘                  │
│                                                    ▲                                 │
│                                                    │                                 │
│                             Security Work Insertion Point: Testing Phase            │
│                             • Adequate time windows                                  │
│                             • Clear phase boundaries                                 │
│                             • Can accommodate high-investment activities             │
│                                                                                      │
│  ═══════════════════════════════════════════════════════════════════════════════════ │
│                                                                                      │
│  【AI-Assisted Development Model (Vibe Coding)】                                     │
│  ─────────────────────────────────────────────────────────────────────────────────── │
│                                                                                      │
│   Requirements/Intent ◄─────────────────────────────────► Code Generation ──► Release│
│       │                      Main Loop (70%+)                    │         5%       │
│       │         ┌─────────────────────────────────┐              │                  │
│       └────────►│  Requirements/Design ↔ Code+Test│◄─────────────┘                  │
│                 │  (Intent description → AI       │                                 │
│                 │   generation → Review)          │                                 │
│                 │  Testing embedded in coding,    │                                 │
│                 │  not independent phase          │                                 │
│                 └─────────────────────────────────┘                                 │
│                              ▲                                                       │
│                              │                                                       │
│               Traditional Security Work Insertion Point?                             │
│               • Testing phase compressed/disappeared                                 │
│               • Phase boundaries blurred                                             │
│               • Cannot accommodate long-cycle security activities                    │
│                                                                                      │
│  ═══════════════════════════════════════════════════════════════════════════════════ │
│                                                                                      │
│  【Structural Change Analysis】                                                      │
│  ─────────────────────────────────────────────────────────────────────────────────── │
│                                                                                      │
│   ┌────────────────┬────────────────────┬────────────────────────────────────────┐  │
│   │   Dimension    │  Traditional Model │  AI-Assisted Model                     │  │
│   ├────────────────┼────────────────────┼────────────────────────────────────────┤  │
│   │ Main loop      │ Coding ↔ Testing   │ Requirements/Design ↔ Code             │  │
│   │ Testing phase  │ Independent phase, │ Embedded in coding,                    │  │
│   │                │ adequate time      │ automated execution                    │  │
│   │ Phase boundaries│ Clear             │ Blurred                                │  │
│   │ Iteration cycle│ Days/weeks         │ Minutes/hours                          │  │
│   │ Security       │ Testing phase      │ Disappeared or fragmented              │  │
│   │ insertion point│ (clear)            │                                        │  │
│   │ Security work  │ Batch, periodic    │ Requires real-time, continuous         │  │
│   │ mode           │                    │                                        │  │
│   └────────────────┴────────────────────┴────────────────────────────────────────┘  │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

**The Imminent Transformation: Main Loop Left-Shifts from "Coding↔Testing" to "Requirements/Design↔Code"**

In the traditional model, developers' primary work was writing code and verifying through tests. Coding and testing were relatively independent activities, executed by different personnel or at different times. This separation provided natural insertion points for security work—during the testing phase, security teams had time and opportunity to execute threat modeling, penetration testing, and security audits.

In the AI-assisted model (Vibe Coding):

1. **Coding costs drastically reduced**: Developers describe intent, AI generates code
2. **Testing embedded in coding process**: AI-generated code typically includes tests, or developers immediately run tests for verification
3. **Main loop left-shifts**: Developers' primary work becomes "describing requirements/design" and "reviewing/adjusting AI-generated code"
4. **Traditional testing phase compressed**: Independent, long-cycle testing phases are compressed or disappear entirely

This structural change leads to: **traditional security work loses appropriate process insertion points and gate positions**.


### **3.2 The Crisis of Security Workflow Embedding**

Traditional security activities were designed assuming: there exists a sufficiently long phase (typically testing) that can accommodate the following work:

| Security Activity | Typical Time Investment | Traditional Insertion Point | Status in AI-Assisted Model |
|------------------|------------------------|----------------------------|----------------------------|
| **Threat Modeling** | 1-3 days/module | Design/Testing phase | Phase boundaries blurred, difficult to schedule |
| **Security Code Review** | 2-4 hours/PR | Development phase | Code generation speed exceeds review capacity |
| **Penetration Testing** | 1-4 weeks/system | Testing phase | Testing phase compressed |
| **Security Audit** | 2-4 weeks/project | Pre-release | Release cycles compressed |
| **Compliance Check** | 1-2 weeks/project | Testing/Release phase | Insufficient time windows |

When the development main loop left-shifts, these security activities dependent on "testing phase time windows" face structural challenges:

1. **Time windows disappear**: Extensive test automation and further process-coding integration eliminate the complete "testing phase"
2. **Speed mismatch**: AI generates modules in minutes, traditional security activities require days/weeks
3. **Process fragmentation**: Security activities cannot find appropriate insertion points
4. **Personnel bottleneck**: Security experts cannot keep pace with code generation speed


### **3.3 Structural Gap in Security Response Speed**

Traditional security processes were designed around manual coding speeds. Threat modeling meetings require hours of expert discussion; SAST scan reports require days of manual review; penetration testing cycles are measured in weeks. Under past coding speeds, these cycles were acceptable.

When AI increases coding speed by an order of magnitude, the response speed gap of security measures becomes significant:

1. **Insufficient real-time capability**: When AI generates new modules in minutes, traditional "convene experts, schedule meetings, whiteboard drawings" threat modeling processes cannot be embedded in CI/CD pipelines
2. **AI generation risks**: AI may "hallucinate" non-existent dependency packages (Package Hallucination), or reuse outdated, vulnerable code patterns from training data (e.g., hardcoded credentials, deprecated encryption algorithms)
3. **Business logic understanding gap**: AI-generated code may be syntactically correct but have business logic flaws (e.g., correctly implementing payment deduction logic but ignoring negative amount boundary cases)


### **3.4 Non-Linear Growth of Code Complexity**

This productivity improvement carries security-related costs: **non-linear growth of code complexity**.

AI models tend to generate structurally complete, fully functional code, but may introduce libraries, patterns, and dependencies that developers don't fully understand. A single requirement may generate hundreds of lines of code involving multiple third-party library interactions. The system's attack surface expands while developers may lack awareness of security implications within.


### **3.5 Systemic Challenges Facing Traditional Threat Modeling**

Synthesizing the above analysis, challenges facing traditional STRIDE and threat modeling methods in AI-assisted programming environments can be summarized as:

| Challenge Dimension | Specific Manifestation | Root Cause |
|--------------------|----------------------|------------|
| **Process embedding crisis** | Cannot find appropriate execution timing | Main loop left-shift, testing phase compression |
| **Speed mismatch** | Analysis speed far below generation speed | Human-driven vs. AI-driven |
| **Expert bottleneck** | Expert numbers cannot match code growth | Limited security talent supply |
| **Methodology obsolescence** | Underlying assumptions (phase separation) no longer hold | Designed for traditional development processes |

**Core Problem**: Traditional threat modeling methodologies were designed for "development processes with clear phase boundaries." When this premise is disrupted by AI-assisted programming, the methodology itself requires restructuring, not just acceleration.

Security systems must possess response speed and understanding depth matching AI generation capabilities—this is precisely the design objective of the skill-threat-modeling project.


---

## **Chapter 4: Architecture and Design Principles of skill-threat-modeling**

### **Design Philosophy: LLM Autonomous Drive and the "Context, not Control" Principle**

To address the research and development transformation wave and new challenges brought by Vibe Coding, we designed this automated toolset named skill-threat-modeling. skill-threat-modeling is an open-ended Agent Skillset that can easily be transformed into equivalent Agent workflows. Its core knowledge base system can also supplement and support other AI-driven systems.

The core design philosophy of skill-threat-modeling can be summarized as: **LLM autonomous drive, context empowerment, open workflow, integrated knowledge system**. This philosophy differs from traditional security tools' "rule-driven, mandatory constraint" patterns.

Traditional security tools typically adopt a "control" paradigm: predefined detection rules, mandatory process execution, fixed-format report output. Tool capability boundaries are determined by rule library coverage. This pattern is effective for handling known patterns but often has limitations facing novel attack vectors or complex business logic.

skill-threat-modeling adopts a knowledge-base-guided intent-aware context paradigm: **clarify goals and intentions, provide information reference and guidance, rather than strictly controlling processes**. The core philosophy is:

1. **LLMs possess reasoning capabilities**: Large language models like Claude have code comprehension, logical reasoning, and attack path construction capabilities. The Skill's role is not to replace these capabilities but to enhance and guide them;
2. **Context defines objectives**: Each phase's Skill provides intent definition, knowledge reference, and output expectations for that phase, not step-by-step operational instructions;
3. **Knowledge base empowers decisions**: Security knowledge bases (CWE, CAPEC, ATT&CK, etc.) serve as reference resources for LLM flexible querying and citation, not mandatory mapping rules;

**Practical implications of the "Context, not Control" principle**:

| Dimension | Control Mode | Context Mode |
|-----------|-------------|--------------|
| **Execution logic** | Predefined rule-driven | LLM reasoning-driven |
| **Process constraints** | Mandatory step sequences | Phase objective-oriented |
| **Knowledge application** | Rule library matching | Knowledge base query reference |
| **Output format** | Fixed templates | Structured but flexible |
| **Extension capability** | Depends on rule updates | Depends on LLM reasoning |

This design enables skill-threat-modeling to adapt to various technology stacks and business scenarios. For example, facing a project using an uncommon framework, traditional rule-based tools might fail due to lacking corresponding rules; while the Context mode Skill can complete analysis through LLM's semantic understanding of the code.

---

The core architecture of skill-threat-modeling is based on **First Principles**—stripping away existing forms to analyze the essence of problems.


### **4.1 Design Strategies for Addressing Development Main Loop Left-Shift**

Based on Chapter 3's analysis, skill-threat-modeling proposes the following design strategies for the "development main loop left-shift" problem:

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│           skill-threat-modeling Design Strategies for Main Loop Left-Shift           │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│  【Problems with Traditional Security Work】                                         │
│  ─────────────────────────────────────────────────────────────────────────────────── │
│   • Depends on independent testing phase as insertion point                          │
│   • Human-driven, slow response speed                                                │
│   • Batch execution, cannot be continuous                                            │
│   • Disconnected from development workflow                                           │
│                                                                                      │
│  【skill-threat-modeling Design Responses】                                          │
│  ─────────────────────────────────────────────────────────────────────────────────── │
│                                                                                      │
│   ┌────────────────────────────────────────────────────────────────────────────┐    │
│   │  Strategy 1: Synchronize with Code (Code-First)                            │    │
│   │  ────────────────────────────────────────────────────────────────────────  │    │
│   │  • Analyze source code directly, don't wait for design documents           │    │
│   │  • Threat modeling can execute immediately after code generation           │    │
│   │  • No dependency on independent testing phase                              │    │
│   │  • Can embed in AI programming environment's real-time workflow            │    │
│   └────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                      │
│   ┌────────────────────────────────────────────────────────────────────────────┐    │
│   │  Strategy 2: AI-Driven Analysis (LLM Autonomous)                           │    │
│   │  ────────────────────────────────────────────────────────────────────────  │    │
│   │  • Use AI to analyze AI-generated code                                     │    │
│   │  • Response speed matches code generation speed                            │    │
│   │  • No need for human experts' full participation                           │    │
│   │  • Can be automated, continuously executable                               │    │
│   └────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                      │
│   ┌────────────────────────────────────────────────────────────────────────────┐    │
│   │  Strategy 3: Integrate into New Main Loop (Integrated Workflow)            │    │
│   │  ────────────────────────────────────────────────────────────────────────  │    │
│   │  • Adapt to "Requirements/Design ↔ Code" new main loop                     │    │
│   │  • Can trigger immediately after code generation                           │    │
│   │  • Support incremental analysis and continuous threat modeling             │    │
│   │  • Output can directly guide next round of code generation                 │    │
│   └────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                      │
│   ┌────────────────────────────────────────────────────────────────────────────┐    │
│   │  Strategy 4: Knowledge Density Enhancement (Knowledge Density)             │    │
│   │  ────────────────────────────────────────────────────────────────────────  │    │
│   │  • Encode scattered security expert knowledge into structured,             │    │
│   │    strongly-logical knowledge bases                                        │    │
│   │  • Reduce dependency on scarce expert experience                           │    │
│   │  • Improve analysis efficiency through knowledge reuse                     │    │
│   │  • Ensure consistency of analysis quality                                  │    │
│   └────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                      │
│  【New Security Work Embedding Model】                                               │
│  ─────────────────────────────────────────────────────────────────────────────────── │
│                                                                                      │
│   Requirements/Intent ◄───────────────────────────────► Code Generation ──► Release │
│       │                      Main Loop                       │                      │
│       │         ┌─────────────────────────────────┐          │                      │
│       └────────►│  Requirements/Design ↔ Code+Test│◄─────────┘                      │
│                 │         ▲         │             │                                  │
│                 │         │         │             │                                  │
│                 │         │         ▼             │                                  │
│                 │    ┌────────────────────┐       │                                  │
│                 │    │ skill-threat-      │       │                                  │
│                 │    │ modeling           │       │                                  │
│                 │    │ (Real-time/        │       │                                  │
│                 │    │  Continuous Threat │       │                                  │
│                 │    │  Analysis)         │       │                                  │
│                 │    └────────────────────┘       │                                  │
│                 └─────────────────────────────────┘                                  │
│                                                                                      │
│   Security work insertion point: Synchronized with code generation,                  │
│   integrated into main loop                                                          │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### **4.2 Code as Primary Analysis Object (Code-First Principle)**

The main problem with traditional threat modeling is the disconnect between analysis objects (design documents) and actual systems (running code). **Code itself is the single source of truth for system state**.

From this follows: all architecture diagrams, data flow diagrams (DFD), and trust boundaries should be **real-time mappings** of code—derived information from code, not manually drawn static images. When code changes, derived information should automatically update.

skill-threat-modeling doesn't depend on user-provided design documents but directly scans project source code. Through code reading, dependency analysis, and semantic understanding, the system reverse-engineers architecture models reflecting current code state. Threat modeling becomes a continuous process that can automatically refresh with each code commit.

> **Note: Code-First ≠ Code-Only**
>
> Clarification is needed here: **Code-First is a priority declaration, not an exclusivity constraint**.
>
> skill-threat-modeling treats code as the priority and core analysis object, but not the only input. The Skill also supports the following input types:
>
> | Input Type | Applicable Scenario | Analysis Method |
> |------------|---------------------|-----------------|
> | **Source Code** | Security assessment of existing codebases | Direct code analysis (primary mode) |
> | **Requirements Documents** | Pre-design phase threat modeling | Derive threat scenarios from requirements |
> | **Architecture Design Documents** | High-level design security review | STRIDE analysis based on design |
> | **Flowcharts/Sequence Diagrams** | Business logic security analysis | Data flow threat analysis based on processes |
> | **IaC Configurations** | Cloud infrastructure security assessment | Security configuration audit based on configs |
> | **API Specifications (OpenAPI)** | Interface security design review | Threat enumeration based on interface definitions |
> | **Software-Defined Everything** | Digitized and software-defined formal expressions | Open future for all data-expressible forms |
>
> **Core meaning of Code-First**: When code is available, prioritize code-based analysis because code is the true source of system state; when code isn't available (e.g., design phase), the Skill can equally perform threat analysis based on other input forms.
>
> This flexibility allows skill-threat-modeling to embed at any stage of software development:
> - **Design Phase**: Pre-emptive threat modeling based on requirements and architecture documents
> - **Development Phase**: Real-time threat analysis based on code
> - **Deployment Phase**: Infrastructure security audit based on IaC configurations
> - **Operations Phase**: Security assessment based on running state snapshots of existing system instances

### **4.3 The Core Role of Context**

The essence of security vulnerabilities is often context misalignment and trust relationship transfer failures. For example, directly printing user input to log files might be a feature in local debug mode but constitutes an information disclosure vulnerability in production. The same code has different security implications within different trust boundaries.

The core advantage of Large Language Models (LLMs) lies in context windows and powerful induction/reasoning capabilities. skill-threat-modeling establishes "context accumulation" and "phased disclosure" principles: **security analysis must be a multi-phase reasoning process**.

From holistic project understanding ("this is a Django web application"), to component interaction analysis ("the user authentication module uses JWT"), to specific code line review ("verify=False here disables signature verification")—context flows, inherits, and enhances across phases. Complete context enables AI Agents to accurately judge whether specific behaviors constitute actual threats.


### **4.4 Validation as the Value Standard**

The security field has false positive problems. Traditional SAST tools may report thousands of "potential issues," most being false positives or theoretical risks that cannot be actually exploited. Developers develop "alert fatigue."

skill-threat-modeling introduces the "validation as value" principle: **threats that cannot be validated are noise; only risks with provable exploitability have practical significance**.

The system requires not only identifying threats but also generating **evidence chains** for each high-risk item—specific attack paths and proofs of concept (POC). If inferred threats cannot construct feasible attack chains, their priority in final reports is downgraded or excluded.

This changes security tools' delivery standards: from "reporting problems" to "proving problems."

Continuously enhancing the validation module is also a primary optimization direction for skill-threat-modeling's future evolution.


### **4.5 Modular Capability Orchestration**

Facing complex security analysis tasks, single general-purpose models struggle to fit all scenarios. skill-threat-modeling decouples security expert capabilities into atomic, reusable skill modules.

"Drawing DFDs" is a skill, "querying CWE databases" is a skill, "constructing SQL injection payloads" is also a skill. Through skill modularization and Claude Code dynamic orchestration, the system can adapt to various technology stacks (Java/Python/Go) and business scenarios (financial payments/healthcare/industrial control).

In fact, skill-threat-modeling's core technology is establishing an independent logic and knowledge system by structuring software security engineering knowledge in formats and languages that LLMs easily understand (including built-in embeddings), and empowering LLMs with the ability to flexibly understand based on context—serving as the LLM's security expert external brain.


### **4.6 Relationship Between Process Constraints, Knowledge Base, and LLM Autonomous Decision-Making**

Understanding skill-threat-modeling's design requires clarifying the relationship between three core components:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│           Collaborative Model: Process Constraints, Knowledge Base & LLM         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    8-Phase Workflow (Process Constraints)                │   │
│  │                                                                          │   │
│  │   Function: Provide necessary path specifications, ensure analysis       │   │
│  │             completeness and output consistency                          │   │
│  │   Nature: Phase boundaries and output format constraints,                │   │
│  │           not mandatory step instructions                                │   │
│  │   Analogy: Navigation system provides route planning,                    │   │
│  │            driving decisions are made autonomously by driver (LLM)       │   │
│  │                                                                          │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                      │                                          │
│                                      │ Define phase objectives                  │
│                                      ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │                        LLM Autonomous Decision Engine                     │  │
│  │                                                                           │  │
│  │  • Code semantic understanding: Understand business logic and data flow  │  │
│  │  • Threat reasoning: Derive attack vectors based on context              │  │
│  │  • Path construction: Design attack chains and POC                       │  │
│  │  • Priority judgment: Assess risk severity and exploitability            │  │
│  │  • Mitigation suggestions: Generate tech-stack-specific remediation      │  │
│  │                                                                           │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                      ▲                                          │
│                                      │ Provide knowledge reference              │
│                                      │                                          │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    Dual-Track Knowledge System (Knowledge Base)          │   │
│  │                                                                          │   │
│  │   Function: Provide security knowledge needed for analysis and           │   │
│  │             decision-making, not Standard Operating Procedures (SOP)     │   │
│  │   Content: CWE/CAPEC/ATT&CK/CVE, Security Control Sets,                 │   │
│  │            Verification Sets                                             │   │
│  │   Nature: Reference resources, queried and applied by LLM as needed     │   │
│  │   Analogy: Expert consultant provides knowledge consultation,            │   │
│  │            decisions made autonomously by operator (LLM)                 │   │
│  │                                                                          │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
│  ═══════════════════════════════════════════════════════════════════════════   │
│                                                                                  │
│  Design Principles Summary:                                                      │
│  ─────────────────────────────────────────────────────────────────────────      │
│  • Process constraints provide "What to do," not mandating "How to do it"       │
│  • Knowledge base provides "What can be referenced,"                             │
│    generally not mandating "What must be followed"                               │
│  • LLM autonomously completes understanding, reasoning, decision-making,         │
│    and generation with constraint and knowledge support                          │
│  • This design enables Skill to adapt to continuous LLM capability improvements  │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Core Design Philosophy**:

1. **Process constraints are not SOPs**: The 8-phase workflow defines logical boundaries and output specifications for analysis, not step-by-step operational instructions. The LLM has full autonomous space within each phase to decide analysis methods and depth.

2. **Knowledge base is not a rule library**: The dual-track knowledge system provides structured security knowledge, not mandatory matching rules. The LLM judges based on context which knowledge to query and how to apply it.

3. **LLM is the decision-making subject**: All substantive security judgments—whether code has vulnerabilities, whether attack paths are feasible, whether remediation plans are effective—are completed by the LLM based on context and knowledge.

The advantage of this design: as LLM capabilities improve, Skill analysis quality improves synchronously, without frequent rule library updates or process restructuring.


---

## **Chapter 5: 8-Phase Security Engineering Workflow: From Macro Analysis to Micro Validation**

### **5.1 Design Objectives**

Another core design of skill-threat-modeling addresses fundamental problems of traditional methods by defining a simple, practical engineering methodology:

1. **Fully automated deep risk analysis**: Complete the entire process from code understanding, architecture reconstruction, threat identification to risk validation without human intervention; can be embedded in CI/CD pipelines;
2. **Low false positive rate**: Through multiple validation logic and deduplication algorithms, each risk in reports has evidence support;
3. **Knowledge traceability and standardization**: All findings can be traced to authoritative security standards (CWE, CAPEC, ATT&CK), with remediation recommendations matching specific technology stacks;
4. **AI programming environment integration**: Can integrate into AI programming environments like Claude Code for real-time auditing of AI-generated code;


### **5.2 Detailed skill-threat-modeling 8-Phase Workflow**

skill-threat-modeling adopts a macro-to-micro, progressively deepening **8-phase strict sequential execution** workflow.

```
┌────────────────────────────────────────────────────────────────────────────────────┐
│                          8-Phase Workflow Pipeline                                  │
├────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  Phase 1      Phase 2      Phase 3      Phase 4      Phase 5      Phase 6     ...  │
│  Project  ──► Call Flow ──► Trust    ──► Security ──► STRIDE  ──► Risk     ──►     │
│  Understanding    DFD      Boundaries    Design     Analysis    Validation         │
│                                                                                     │
│       │                                                              │              │
│       └──────────── Context Accumulation ────────────────────────────┘              │
│                                                                                     │
│  ...   Phase 7      Phase 8                                                         │
│  ──► Mitigation ──► Report                                                          │
│       Planning     Generation                                                       │
│                                                                                     │
└────────────────────────────────────────────────────────────────────────────────────┘
```

#### **Phase 1: Project Understanding**

Establish holistic cognition of the target system.

- **Input**: Project source code root directory (or requirements documents, architecture design documents, etc. as alternative inputs)
- **Core Actions**:
  - Scan file structure, identify programming languages and technology stack
  - Analyze framework characteristics (Django/Spring Boot/Express, etc.)
  - Extract dependency declarations (package.json/requirements.txt/pom.xml)
  - Locate key entry points (main functions, route registrations, event handlers)
- **Output**: `P1-PROJECT-UNDERSTANDING.md`, containing technology stack fingerprint, core component list, and preliminary security observations
- **Functional Value**: Establish baseline context for subsequent phases

#### **Phase 2: DFD Analysis (Data Flow Diagram Reverse Engineering)**

**Reverse-engineer** data flow diagrams from code.

- **Input**: P1 output + source code
- **Core Actions**:
  - Trace data flow paths between components
  - Identify external entities (users, third-party APIs), processes (business logic modules), data stores (databases, caches, file systems)
  - Draw data flows and their carried information types
- **Output**: `P2-DFD-ANALYSIS.md`, containing Mermaid-format DFD with data flow risk annotations
- **Functional Value**: Transform code into architecture views suitable for STRIDE analysis

#### **Phase 3: Trust Boundary Analysis**

Trust boundaries are key elements in security analysis—data flows crossing boundaries are common attacker entry points.

- **Input**: P2 output + source code
- **Core Actions**:
  - Identify trust boundaries (Internet ↔ DMZ, frontend ↔ backend, user space ↔ kernel space)
  - Analyze sanitization and validation mechanisms when data crosses boundaries
  - Mark unprotected or insufficiently protected boundary crossing points
- **Output**: `P3-TRUST-BOUNDARY.md`, containing boundary-annotated architecture diagram and unprotected crossing point list
- **Functional Value**: Provide attack surface map for subsequent STRIDE analysis

#### **Phase 4: Security Design Review**

Before analyzing specific vulnerabilities, evaluate the system's security mechanism design.

- **Input**: P1-P3 outputs
- **Core Actions**:
  - Review architecture design against 11 security principles (defense in depth, least privilege, zero trust, etc.)
  - Evaluate implementation status of core security functions: authentication/authorization/auditing/encryption
  - Identify architecture-level systemic deficiencies
- **Output**: `P4-SECURITY-DESIGN-REVIEW.md`, containing security capability coverage matrix and architecture-level gap analysis
- **Functional Value**: Discover **systemic design defects** difficult to find through code review

#### **Phase 5: STRIDE Threats (Automated Threat Enumeration)**

Automated implementation of STRIDE methodology—mapping each element and interaction in DFD to six threat categories.

- **Input**: P2 (DFD) + P3 (Trust Boundaries)
- **Core Actions**:
  - Apply STRIDE matrix to each element (Process/DataStore/DataFlow) in DFD
  - Systematically generate threat questions
  - Assign unique identifiers to each threat (e.g., `T-S-P01-001`)
- **Output**: `P5-STRIDE-THREATS.md`, comprehensive threat list
- **Functional Value**: Automate work that traditionally requires hours of expert discussion

#### **Phase 6: Risk Validation — Core Phase**

Phase 6 is the **critical pivot** of the workflow, the core differentiator from traditional tools. The task is: **filter, consolidate, and validate "potential risks" from preceding phases into "confirmed risks"**.

> **Note**: P6 is the **risk validation** phase, not the mitigation phase. Attack chain analysis and POC design are completed in this phase.

- **Input**: All finding files from P1-P5

**Core Process 1: Consolidation Algorithm**

Since preceding phases may discover the same problem from different angles, the consolidation algorithm eliminates duplicates and noise:

1. **Normalization**: Convert findings in different formats from P1-P5 into standardized `normalized_finding` objects, using rules to infer missing CWE IDs
2. **Deduplication**:
   - **Exact Match → MERGE**: CWE ID and file path completely identical, treated as same risk, merged with highest severity
   - **Component Match → LINK**: Same CWE but different files, categorized as systemic issue within same component
   - **Similarity Match**: Use text similarity algorithm (threshold 0.85) to identify similar description duplicates
3. **Count Conservation (Threat Disposition Tracking)**: Ensure each STRIDE threat from P5 has clear disposition in final report—converted to validated risk (VR-xxx) or marked as mitigated/excluded

**Core Process 2: Validation Logic (via Parallel Sub-Agents)**

- Launch parallel sub-agents for consolidated high-risk items:
  - Query knowledge base for related CAPEC attack patterns and ATT&CK techniques
  - Query verification sets (WSTG/MASTG) for specific test steps
- **Attack Path Design**: Construct complete attack chains from entry point to final impact
- **POC Design**: Build specific attack payloads or reproduction steps for Critical/High level threats

**Output**: `P6-RISK-VALIDATION.md`, containing:
- Validation coverage statistics (validation rate, exclusion rate)
- Attack path feasibility matrix
- Attack chain analysis (with flowcharts)
- POC details (for each Critical/High threat)
- Validated risk list (VR-xxx format)

**Functional Value**: Embodies the "validation as value" principle—only risks with provable exploitability enter the final report.

#### **Phase 7: Mitigation Planning**

After P6 validates risk authenticity, enter the mitigation design phase.

- **Input**: P6 validated risk list (`validated_risks`)
- **Core Actions**:
  - Design immediate, short-term, long-term three-tier mitigation strategies for each validated risk
  - Generate code-level remediation recommendations matching specific technology stacks
  - Priority ordering and effort estimation
- **Knowledge References**: Security Control Sets + OWASP References + CWE Mitigations + ASVS Requirements
- **Output**: Mitigation plan including implementation priorities, estimated effort, and specific code remediation guidance

#### **Phase 8: Final Reporting (Report Generation and Compliance Mapping)**

Integrate all analysis outputs into a structured report suite.

- **Input**: All preceding phase outputs
- **Output**: Complete threat modeling report suite, output to `Risk_Assessment_Report/` directory:
  - Main Report: `{PROJECT}-RISK-ASSESSMENT-REPORT.md` — Executive summary, key findings, recommendation priorities
  - Risk Inventory: `{PROJECT}-RISK-INVENTORY.md` — Detailed technical information for all validated risks
  - Mitigation Measures: `{PROJECT}-MITIGATION-MEASURES.md` — Remediation guide and implementation roadmap
  - Penetration Test Plan: `{PROJECT}-PENETRATION-TEST-PLAN.md` — POC-based test cases
  - Phase Process Documents: `P1-P6` detailed analysis documents for each phase, as technical reference for deep-dive problem analysis and process expansion


### **5.3 System Architecture Diagram**

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                          Agent Skill Architecture                                 │
├───────────────────────────────────────────────────────────────────────────────────┤
│                                                                                    │
│   User Request                                                                     │
│        │                                                                           │
│        ▼                                                                           │
│   ┌──────────────────────────────────────────────────────────────────────────┐   │
│   │                     Claude Code (AI Agent Host)                           │   │
│   │  ┌────────────────────────────────────────────────────────────────────┐  │   │
│   │  │              skill-threat-modeling (Claude Skill)                   │  │   │
│   │  │                                                                     │  │   │
│   │  │  ┌─────────────────────────────────────────────────────────────┐  │  │   │
│   │  │  │  Phase 1-3: Context Building                                 │  │  │   │
│   │  │  │  P1 (Project) → P2 (DFD) → P3 (Boundaries)                   │  │  │   │
│   │  │  └─────────────────────────────────────────────────────────────┘  │  │   │
│   │  │                              │                                     │  │   │
│   │  │                              ▼                                     │  │   │
│   │  │  ┌─────────────────────────────────────────────────────────────┐  │  │   │
│   │  │  │  Phase 4-5: Threat Identification                            │  │  │   │
│   │  │  │  P4 (Security Design) → P5 (STRIDE Enumeration)              │  │  │   │
│   │  │  └─────────────────────────────────────────────────────────────┘  │  │   │
│   │  │                              │                                     │  │   │
│   │  │                              ▼                                     │  │   │
│   │  │  ┌─────────────────────────────────────────────────────────────┐  │  │   │
│   │  │  │  Phase 6: Risk Validation (Core)                             │  │  │   │
│   │  │  │  Consolidation → KB Query → Attack Path → POC Design         │  │  │   │
│   │  │  └─────────────────────────────────────────────────────────────┘  │  │   │
│   │  │                              │                                     │  │   │
│   │  │                              ▼                                     │  │   │
│   │  │  ┌─────────────────────────────────────────────────────────────┐  │  │   │
│   │  │  │  Phase 7-8: Remediation & Reporting                          │  │  │   │
│   │  │  │  P7 (Mitigation Planning) → P8 (Report Generation)           │  │  │   │
│   │  │  └─────────────────────────────────────────────────────────────┘  │  │   │
│   │  │                                                                     │  │   │
│   │  └────────────────────────────────────────────────────────────────────┘  │   │
│   │                                                                           │   │
│   │  Tools: Read, Write, Edit, Bash, Glob, Grep, Task (Sub-Agent)            │   │
│   └──────────────────────────────────────────────────────────────────────────┘   │
│                                      │                                            │
│                                      ▼                                            │
│   ┌──────────────────────────────────────────────────────────────────────────┐   │
│   │                        Knowledge Base (Local)                             │   │
│   │  ┌────────────────────┐  ┌────────────────────┐  ┌──────────────────┐   │   │
│   │  │ Security Control   │  │ Threat Pattern     │  │ Verification     │   │   │
│   │  │ Set                │  │ Set                │  │ Set              │   │   │
│   │  │ ───────────────    │  │ ───────────────    │  │ ───────────────  │   │   │
│   │  │ • 16 Domains       │  │ • 974 CWEs         │  │ • 121 WSTG      │   │   │
│   │  │ • 107 Controls     │  │ • 615 CAPECs       │  │ • 206 MASTG     │   │   │
│   │  │ • 74 OWASP Refs    │  │ • 835 ATT&CK       │  │ • 345 ASVS      │   │   │
│   │  │ • 14 Compliance    │  │ • 323K+ CVEs       │  │                  │   │   │
│   │  └────────────────────┘  └────────────────────┘  └──────────────────┘   │   │
│   └──────────────────────────────────────────────────────────────────────────┘   │
│                                                                                    │
└───────────────────────────────────────────────────────────────────────────────────┘
```

**Architecture Notes**:

- skill-threat-modeling is an **Agent Skill** (skill module), running in Claude Code and other compatible environments that support Skill invocation
- Uses native tools supported by Claude Code or other Agents (Read, Write, Edit, Bash, Glob, Grep, Task, etc.) for code analysis and file operations
- Local knowledge base contains three major knowledge sets, is self-contained with no external dependencies, supports offline operation
- Supports launching parallel sub-agents via Task tool for efficient concurrent validation of multiple risk items

---


## **Chapter 6: skill-threat-modeling Knowledge Architecture**

Another core of skill-threat-modeling is not just the workflow, but systematically aggregating security knowledge into "structured" and "executable" knowledge architecture. The core philosophy of skill-threat-modeling's knowledge base is: **transform security knowledge scattered across various standard documents into structured knowledge and methodological logic that LLM/AI Agents can understand, query, reason with, and apply**.

### **6.1 Dual-Track Knowledge Architecture**

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                              Security Knowledge Architecture                        │
├───────────────────────────────────────────────────────────────────────────────────┤
│                                                                                    │
│                       ┌───────────────────────────────────────────┐               │
│                       │         Security Principles (11)          │               │
│                       │    (Foundation - Guides All Phases)       │               │
│                       │  DID │ LP │ ZT │ FS │ SOD │ SBD │ CM │   │               │
│                       │  EOM │ OD │ IV │ LA                       │               │
│                       └───────────────────────────────────────────┘               │
│                                           │                                        │
│                 ┌─────────────────────────┴─────────────────────────┐             │
│                 │                                                    │             │
│                 ▼                                                    ▼             │
│  ┌─────────────────────────────────────┐      ┌─────────────────────────────────┐│
│  │      Security Control Set          │      │      Threat Pattern Set         ││
│  │      (What to do & How to do)      │      │      (What to know & Validate)  ││
│  ├─────────────────────────────────────┤      ├─────────────────────────────────┤│
│  │  Security Domains (16)              │      │  CWE Weakness Types (974)       ││
│  │      │                              │      │      │                          ││
│  │      ▼                              │      │      ▼                          ││
│  │  Control Sets (18 files, 107)       │      │  CAPEC Attack Patterns (615)    ││
│  │      │                              │      │      │                          ││
│  │      ▼                              │      │      ▼                          ││
│  │  OWASP References (74)              │      │  ATT&CK Techniques (835)        ││
│  │      │                              │      │      │                          ││
│  │      ▼                              │      │      ▼                          ││
│  │  Compliance Frameworks (14)         │      │  CVE/KEV Vulnerabilities (323K+)││
│  └──────────────┬──────────────────────┘      └──────────────┬──────────────────┘│
│                 │                                             │                   │
│                 │      ┌─────────────────────────────┐        │                   │
│                 │      │    Verification Set         │        │                   │
│                 │      │  (How to verify & test)     │        │                   │
│                 └─────▶│                             │◀───────┘                   │
│                        │  WSTG Tests (121)           │                            │
│                        │  MASTG Tests (206)          │                            │
│                        │  ASVS Requirements (345)    │                            │
│                        └─────────────────────────────┘                            │
│                                                                                    │
└───────────────────────────────────────────────────────────────────────────────────┘
```

The knowledge architecture adopts a dual-track design, using three sets across two directions for cross-complementation:

**Security Control Set** answers "what to do" and "how to do it":
The Security Control Set progressively defines from security functionality and architecture design best practices perspectives what good and reasonable design and security controls should look like.
- 16 security domains covering authentication, authorization, cryptography, audit logging, and other core functions
- 107 specific control measures
- 74 OWASP references
- 14 compliance frameworks (PCI-DSS, HIPAA, GDPR, etc.)

**Threat Pattern Set** answers "what can go wrong" and "how to validate":
The Threat Pattern Set, from the opposite direction and use cases, summarizes and generalizes where problems/risks and weaknesses come from, what root causes are, and what typical patterns and characteristics exist.
- 974 CWE weakness types
- 615 CAPEC attack patterns
- 835 ATT&CK techniques
- 323K+ CVE vulnerability instances

**Verification Set** is the convergence point of the two tracks, transforming control requirements and threat knowledge into executable tests:
- 121 WSTG (Web Security Testing Guide) test cases
- 206 MASTG (Mobile Application Security Testing Guide) test cases
- 345 ASVS (Application Security Verification Standard) requirements


### **6.2 11 Security Principles**

These principles serve as the foundation layer guiding all phase analyses, and when the hierarchical knowledge base is incomplete, they also serve as baseline rules keeping LLM understanding and thinking at a certain level:

| Code | Principle | Definition |
|------|-----------|------------|
| **DID** | Defense in Depth | Multiple independent security controls; single point failure doesn't compromise system |
| **LP** | Least Privilege | Grant only minimum privileges necessary to complete tasks |
| **ZT** | Zero Trust | No default trust, always verify explicitly; assume network is already compromised |
| **FS** | Fail Secure | Default to most secure state when errors occur |
| **SOD** | Separation of Duties | Critical operations require multiple party participation |
| **SBD** | Secure by Default | Default configuration is secure |
| **CM** | Complete Mediation | Every access must verify authorization |
| **EOM** | Economy of Mechanism | Security mechanisms should be simple and auditable |
| **OD** | Open Design | Security doesn't depend on algorithm or design secrecy |
| **IV** | Input Validation | All external input must be validated before processing |
| **LA** | Least Agency | Limit AI Agent autonomy, tool access, and decision scope |


### **6.3 Threat Intelligence Chain**

A key design of the knowledge architecture is the **Threat Intelligence Chain**—progressively mapping abstract STRIDE categories to specific threat knowledge:

```
STRIDE Category ──► CWE Weakness ──► CAPEC Attack Pattern ──► ATT&CK Technique ──► CVE/KEV
       │                 │                   │                      │                  │
       S             CWE-287            CAPEC-151                T1078            CVE-xxxx
       T             CWE-89             CAPEC-66                 T1190            KEV check
       R             CWE-778            CAPEC-93                 T1070
       I             CWE-200            CAPEC-116                T1552
       D             CWE-400            CAPEC-125                T1498
       E             CWE-269            CAPEC-122                T1548
```

When the Agent discovers a "Tampering" threat in P5, it can follow this chain:
1. Map to CWE-20 (Improper Input Validation)
2. Query CAPEC for related SQL injection attack patterns (CAPEC-66)
3. Locate in ATT&CK the "Initial Access" tactic (T1190: Exploit Public-Facing Application)

This **chain reasoning** gives tool output rich background and tactical significance in threat intelligence.

### **6.4 From Static Standards to Dynamic Verification Sets**

Traditional security standards (like OWASP WSTG, MASTG) exist as PDFs or web pages. skill-threat-modeling introduces the "Verification Set" concept, transforming these standards into **machine-readable, queryable, executable** instruction sets.

During the P6 phase, the Agent can query specific WSTG chapters (e.g., WSTG-ATHN-04: Testing for Bypassing Authentication Schema) to:
1. Extract standard test procedures defined in that chapter
2. Generate customized test cases combining current code context
3. Apply these test steps in POC design

This achieves **dynamic application of security knowledge**: standards are no longer reference documents but active knowledge sources directly participating in each analysis.


---

## **Chapter 7: Flexible Application Modes: Beyond the 8-Phase Workflow**

skill-threat-modeling's 8-phase workflow is the main process designed for complete threat modeling tasks. However, the Skill's core value—**structured security knowledge system**—supports multiple flexible application modes beyond the fixed main workflow. Users can trigger skill-threat-modeling and flexibly leverage its partial capabilities and knowledge base for scenarios, enabling LLM and skill-threat-modeling to construct any desired security-related tasks, including but not limited to: solution design, architecture planning, knowledge Q&A, risk analysis, and automated testing.

**After explicitly or implicitly triggering skill-threat-modeling, you can directly initiate prompts and extended requirement dialogues in conversations with the agent/LLM. Below are some typical usage scenarios:**

### **7.1 Knowledge Base Consultation Mode**

Use the knowledge base as a security consulting resource without executing the complete workflow.

**Applicable Scenarios**:
- Developers encountering security-related questions during coding need quick authoritative reference
- Security auditors need to understand attack patterns and mitigations for specific vulnerability types
- Architects need security best practice references during design

**Usage Example**:
```
User: Query complete information for CWE-89 (SQL Injection),
including common attack patterns, testing methods, and mitigations

Response:
- CWE-89 overview and technical background
- Related CAPEC attack patterns (CAPEC-66, CAPEC-7, CAPEC-108)
- WSTG testing steps (WSTG-INPV-05)
- ASVS compliance requirements
- Tech-stack-specific mitigation code examples
```

### **7.2 Deep Vulnerability Analysis Mode**

Conduct in-depth analysis of specific vulnerability types or code snippets.

**Applicable Scenarios**:
- SAST tools reported potential vulnerabilities, need deeper assessment of actual risk
- Penetration testing found suspicious points, need to construct complete attack paths
- Security researchers analyzing exploitability of specific vulnerabilities

**Usage Example**:
```
User: Analyze SSRF risk in this code, construct attack path and design POC
[Code snippet]

Response:
- Vulnerability mechanism analysis
- Attack path construction (Entry Point → Impact)
- POC design (including specific Payload)
- Exploitation conditions and limitations analysis
- Mapping to CWE/CAPEC/ATT&CK
```

### **7.3 Security Test Generation Mode**

Generate security test cases based on knowledge base.

**Applicable Scenarios**:
- Need to generate automated security tests for CI/CD pipelines
- Prepare test checklists before penetration testing
- Security training requires practical case demonstrations

**Usage Example**:
```
User: Generate WSTG-based security test cases for this API endpoint

Response:
- Authentication test cases (WSTG-ATHN)
- Authorization test cases (WSTG-ATHZ)
- Input validation test cases (WSTG-INPV)
- Session management test cases (WSTG-SESS)
- Each test case includes: objective, steps, expected results, payload examples
```

### **7.4 Forward Integration: Design-Phase Security**

Conduct pre-emptive threat modeling during design phase without waiting for code completion.

**Applicable Scenarios**:
- Security architecture design for new projects
- Security impact assessment for major feature changes
- Systematic organization of security requirements

**Usage Example**:
```
User: Conduct STRIDE threat analysis based on this API specification (OpenAPI)
[OpenAPI specification]

Response:
- DFD constructed based on API endpoints
- Trust boundary identification (authenticated/unauthenticated endpoints)
- STRIDE threat enumeration for each endpoint
- Design-phase security recommendations
```

### **7.5 Backward Integration: Penetration Testing Support**

Provide attack path and POC design support for penetration testing.

**Applicable Scenarios**:
- Pre-planning for penetration tests
- Deep exploitation after discovering vulnerabilities
- Technical evidence generation for security assessment reports

**Usage Example**:
```
User: I found JWT signature verification bypass in the target system,
help me construct complete attack chain

Response:
- Vulnerability confirmation steps
- Attack chain construction (Bypass → Privilege Escalation → Data Access)
- POC payload generation
- Impact assessment
- ATT&CK mapping and report template
```

### **7.6 Mode Selection Guide**

| Application Mode | Input Form | Output Form | Applicable Stage |
|-----------------|------------|-------------|-----------------|
| **Complete Workflow** | Codebase | Complete threat modeling report | During development/pre-release |
| **Knowledge Base Consultation** | Question/query | Structured knowledge response | Any stage |
| **Deep Vulnerability Analysis** | Code snippet/vulnerability description | Attack path + POC | Code review/penetration testing |
| **Security Test Generation** | Target description/code | Test case checklist | Testing phase |
| **Forward Integration** | Design documents/specifications | Design-phase threat analysis | Design phase |
| **Backward Integration** | Discovered vulnerability | Attack chain + exploitation plan | Penetration testing |

**Core Value**: skill-threat-modeling's core asset is its **comprehensive security knowledge system**. The 8-phase workflow is one application form of this knowledge system, not the only one. Users can flexibly select the most appropriate application mode based on actual needs.

---


## **Chapter 8: Summary of skill-threat-modeling Core Features and Differences from Traditional Security Engineering**

### **8.1 Solutions to Traditional Problems**

| Traditional Problem | skill-threat-modeling Solution |
|--------------------|-------------------------------|
| **Documentation-code disconnect** | Code-First architecture: Prioritize reverse-engineering DFD from source code, while supporting multiple input forms |
| **Expert resource constraints** | Encode expert knowledge into executable Skills, lowering threat modeling skill barriers |
| **Missing verification closed loop** | Phase 6 risk validation mechanism: Design attack paths and POC for each high-risk item |
| **High false positive rate** | Consolidation algorithm + count conservation validation |
| **Cannot embed in CI/CD** | Fully automated design, can serve as pipeline step for continuous threat modeling |
| **Unstructured knowledge** | Dual-track knowledge system + threat intelligence chain |
| **Speed gap** | AI-native architecture, synchronized with AI code generation |
| **Theory-practice disconnect** | 8-phase strict workflow, complete closed loop from understanding to validation |
| **Single usage scenario** | Multiple flexible application modes adapting to different stages and needs |
| **Process insertion point disappearance** | Code-First + AI-driven, adapting to new development main loop |

### **8.2 Core Differentiating Features**

1. **Code-First Rather Than Document-First (Not Code-Only)**
   - Traditional approach: Manually draw DFD → Analyze → Code implementation (may deviate from design)
   - This approach: Prioritize code scanning → Auto-generate DFD → Analyze (always consistent with implementation)
   - Also supports requirements documents, architecture diagrams, IaC configurations, and other input forms

2. **8-Phase Strict Workflow**
   - Progressive analysis from macro (project understanding) to micro (POC design)
   - Each phase has clear inputs, outputs, and quality standards
   - Context accumulates and transfers between phases

3. **Consolidation Algorithm**
   - Exact Match MERGE: Multi-angle discoveries of same problem intelligently merged
   - Component Match LINK: Systemic problems identified and categorized
   - Count conservation guarantee: Every STRIDE threat has clear disposition

4. **Threat Intelligence Chain Reasoning**
   - STRIDE → CWE → CAPEC → ATT&CK → CVE/KEV
   - Complete traceability path from abstract category to specific vulnerability, can generate attack chains and penetration test cases based on actual validation results

5. **Verification Set Integration**
   - WSTG (121 items) / MASTG (206 items) / ASVS (345 items)
   - Transform industry standards into executable test instructions, can directly integrate into software testing and auto-generate test cases

6. **Attack Path Design and POC Generation**
   - Not just reporting "risk may exist"
   - But proving "how risk can be exploited," and "how to validate" and "how to mitigate"

7. **Local Knowledge Base Supporting Offline Operation**
   - 974 CWE, 615 CAPEC, 835 ATT&CK, 323K+ CVE (requires extension library)
   - Knowledge system and program system form closed loop, no external API calls needed, suitable for sensitive project analysis

8. **"Context, not Control" Design Philosophy**
   - Process constraints provide path specifications, not mandatory steps
   - Knowledge base provides reference resources, LLM makes autonomous decisions
   - Synchronously enhanced as LLM capabilities improve

9. **Naturally Adapted to AI Era's Extreme Left-Shift of Development Main Loop**
   - Real-time workflow embeddable in AI programming environments
   - No dependency on independent testing phase as insertion point
   - Analysis capability matching code generation speed

---

## **Chapter 9: Future Outlook: Evolution and Changes in Security Engineering Practice**

### **9.1 Democratization and High-Frequency of Threat Modeling**

By encapsulating complex expert knowledge into executable Skills, skill-threat-modeling lowers the skill barrier for threat modeling. Under traditional models, only experts with combined "architecture vision + offensive/defensive depth" capabilities could lead effective threat modeling; under the new paradigm, any developer—or the AI programming assistant itself—can initiate expert-level threat analysis.

This can drive threat modeling's transformation from low-frequency activity (quarterly) to high-frequency activity (per commit). **Continuous Threat Modeling** will become a component of DevSecOps practice.

### **9.2 Further Realization of Security Shift-Left**

"Shift Left" is a goal of the security industry—early problem discovery reduces remediation costs. But traditional "shift-left" was constrained by manual costs, making it difficult to truly embed in fast-paced development processes.

As skill-threat-modeling-type tools integrate into AI coding environments, security checks can "shift left" to the moment of code generation. When AI generates code, backend Skills can simultaneously run threat analysis, proposing modification suggestions before code is written to disk, reducing vulnerability creation.

### **9.3 Changes in Security Talent Roles**

When basic discovery, deduplication, and validation work is handled by AI Agents, security expert roles will change. They can shift from tedious log analysis and false positive screening to higher-value work:

- **Designing more advanced Skill logic**: Optimizing consolidation algorithms, designing new detection skills
- **Maintaining core knowledge systems**: Updating Verification Sets, ensuring Agents master latest offensive/defensive techniques
- **Handling high-complexity logic vulnerabilities**: Deep business logic attacks that AI cannot yet understand

---

## **Conclusion**

The skill-threat-modeling project represents a technological upgrade and methodological restructuring of traditional STRIDE threat modeling. Through first-principles reasoning, it establishes the standards of **"code-first, context-driven, verification closed loop"**.

Traditional STRIDE was positioned as a "design phase activity," but industry practice shows: early threat modeling lacking specific implementation information tends toward abstraction; postponing to implementation phase misses early intervention opportunities. More critically, the "independent testing phase" that traditional methods assumed as security work insertion points is compressed or disappears entirely in AI-assisted programming environments.

skill-threat-modeling, through its Code-First approach, prioritizes working on source code while supporting multiple input forms, enabling threat modeling to analyze based on "current system state" at any moment. Its AI-native architecture enables analysis speed to match code generation speed, no longer depending on traditional phased security activity patterns.

Its Claude Skill-based architecture and 8-phase workflow solve the efficiency bottlenecks, cognitive gaps, and process embedding crises that traditional security methods face in the AI era. The "Context, not Control" design philosophy enables the Skill to synchronously enhance as LLM capabilities improve. From project understanding to risk validation, from mitigation planning to report generation, each phase has clear quality standards and traceable outputs. The Consolidation algorithm ensures output precision, the threat intelligence chain provides rich background information, and verification set integration transforms industry standards into executable test instructions.

With further enhancement of AI-assisted development technology and model/Agent/Skill capabilities, software security will increasingly depend on building intelligent, autonomous, knowledge-dense **Agentic Security** ecosystems. When AI Agents can "read" code, "understand" business context, "reason" attack paths, and "prove" risk existence, software security practice will enter a new phase.

---


