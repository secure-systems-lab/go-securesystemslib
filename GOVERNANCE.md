# Go-securesystemslib Project Governance

This document covers the project's governance and committer process. The
project consists of the
[go-securesystemslib](https://github.com/secure-systems-lab/go-securesystemslib)
and related documentation. This governance does **NOT** apply to any other
projects under the [secure-systems-lab](https://github.com/secure-systems-lab)
Github organization.

## Motivation

The goal of the go-securesystemslib project is to be a common foundational
library for cryptographic signing and verifying. We strongly believe a common,
widely reviewed library, will result in a higher quality and more secure
implementaiton. The project, while not limited to, is specifically interested in
the signing and verification of metadata and signing envelopes. Several major
foundation-based open source projects would like to contribute to and consume
this library. The motiviation of this governance is to give these projects the
confidence to invest their time towards collaboration and leverage this library
as a critical and foundational piece of their projects. This goverance will be
as lightweight as possible to allow the project to keep pace with rapidly
evolving technology. It is based on an assumption of goodwill and good intent.

## Code of Conduct

The go-securesystemslib project abides by the Cloud Native Computing Foundation's
[code of conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md).
An excerpt follows:

> We are committed to making participation in the CNCF community a harassment-free
experience for everyone, regardless of age, body size, caste, disability,
ethnicity, level of experience, family status, gender, gender identity and
expression, marital status, military or veteran status, nationality, personal
appearance, race, religion, sexual orientation, socioeconomic status, tribe,
or any other dimension of diversity.

The go-securesystemslib project members represent the project and their fellow
contributors. We value our community tremendously, and we'd like to keep
cultivating a friendly and collaborative environment for our contributors and
users. We want everyone in the community to have a positive experience.

We also interact closely with other open source groups and projects, most
notably the [CNCF projects](https://www.cncf.io/) [in-toto](https://in-toto.io)
and [TUF](https://theupdateframework.io).  Maintaining a productive and healthy
collaborative relationship with projects hosted at other open source foundations
is also a major goal.

## Maintainership

The project is maintained by the people indicated in [MAINTAINERS.md](MAINTAINERS.md).
A maintainer is expected to (1) submit and review GitHub pull requests and (2)
open issues. A maintainer has the authority to approve or reject pull requests
submitted by contributors.

## Changes in maintainership

Active contributors may be offered or request to be granted maintainer status.
This requires approval from a 2/3 majority of currently voting maintainers with at
least a 72 hour public voting period.

Maintainers may be moved to emeritus status.  This is done at the request of the
maintainer moving to emeritus at any time.  Alternatively, moving a maintainer to
emeritus status may be proposed by any maintainer and will be passed with a 2/3
majority of voting maintainers with at least a 72 hour public voting period.  
Emeritus maintainers are listed in the MAINTAINERS.md file as acknowledgment for
their prior service to the project, but no longer have code review, voting, or other
maintainer privileges for the project.

## Project-specific dedicated maintainer roles

Any project that demonstrates a commitment to consuming this library as a
foundational piece of their own project may be eligible for a dedicated maintainer
postion for their project. The role is allocated to a representative of a project.
If that representative ends their relationship with the project, the project will
be able to recommend a new dedicated maintainer. The current set of projects that
meet these requirements are:

| Project                                      | Maintainer |
| -------------------------------------------- | ---------- |
| [In-toto](https://github.com/in-toto)        | TBD        |
| [TUF](https://github.com/theupdateframework) | TBD        |

**Note: Dedicated Maintainer roles are still subject to general maintainer rules*

## Changes in governance

The maintainers supervise changes in governance.  Changes are approved by a 2/3
majority of voting maintainers with a 72 hour public voting / discussion period.
