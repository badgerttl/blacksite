# Upstream licensing review

Reviewed 2026-11-26 against upstream license texts and this repository's Compose
configuration and Dockerfiles. This is a source-based compliance review, not a
legal opinion or a complete audit of every file inside the container images.
Because Blacksite tracks mutable upstream tags and Git refs, these findings must
be checked again when the resolved versions or distribution model change.

## Findings that need attention

1. HackTricks is not cleared for commercial use by this review. Its current FAQ
   contains custom terms, retains third-party content restrictions, and directs
   commercial-use inquiries to the author. Blacksite describes consultancy use,
   so obtain clarification or permission for that use before treating the local
   mirror as commercially cleared. Credit alone does not settle this question.
   Do not label the current content with a Creative Commons license taken from an
   older fork. [HackTricks license section](https://github.com/HackTricks-wiki/hacktricks/blob/master/src/welcome/hacktricks-values-and-faq.md#license).
2. Preserve Open WebUI's product branding. Its current custom license allows
   redistribution subject to notices and a branding condition, with exceptions
   for deployments of at most 50 users within a rolling 30-day period, written
   permission, or a qualifying enterprise license. This repository does not
   configure removal of that branding. An administrator account called Blacksite
   Admin is different from replacing the application's branding.
   [Open WebUI license](https://github.com/open-webui/open-webui/blob/main/LICENSE).
3. Publishing Compose files differs from giving someone copies of built images.
   Acknowledgements do not replace required license texts, notices, or source
   availability arrangements when redistributing software. Follow the applicable
   component's conditions before publishing images or exporting them to clients.
   [MIT example](https://github.com/hoppscotch/hoppscotch/blob/main/LICENSE),
   [Apache-2.0 section 4](https://github.com/gchq/CyberChef/blob/master/LICENSE),
   [AGPL sections 4–6](https://github.com/searxng/searxng/blob/master/LICENSE).

## Included applications

| Project | Upstream terms checked | Implication for Blacksite |
| --- | --- | --- |
| Open WebUI | [Custom Open WebUI License](https://github.com/open-webui/open-webui/blob/main/LICENSE), with [license history](https://github.com/open-webui/open-webui/blob/main/LICENSE_HISTORY) | Preserve copyright/license/disclaimer on redistribution and preserve branding unless an exception applies. Historical materials can have earlier terms. |
| Hoppscotch Community | [Repository-root MIT license](https://github.com/hoppscotch/hoppscotch/blob/main/LICENSE) | Commercial use is permitted under this license; preserve the copyright and permission notice when copying the software. This finding does not cover separate Enterprise products or all third-party dependencies in the image. |
| Proxyscotch | [MIT](https://github.com/hoppscotch/proxyscotch/blob/master/LICENSE) | Preserve copyright and permission notice in distributed copies. |
| CloudBeaver Community | [Apache-2.0](https://github.com/dbeaver/cloudbeaver/blob/devel/LICENSE) | Include the license, retain relevant notices, mark modified files, and preserve any applicable upstream NOTICE. Commercial editions and individual database drivers require separate checks. |
| CyberChef | [Apache-2.0](https://github.com/gchq/CyberChef/blob/master/LICENSE) | Same Apache redistribution obligations; preserve any applicable third-party notices shipped with the image. |
| Reverse Shell Generator | [MIT, Ryan Montgomery](https://github.com/0dayCTF/reverse-shell-generator/blob/main/LICENSE) | Preserve its copyright and permission notice. The existing Dockerfile copies the source root, including LICENSE, to the served directory. |
| HackTricks | [Custom FAQ license and third-party terms](https://github.com/HackTricks-wiki/hacktricks/blob/master/src/welcome/hacktricks-values-and-faq.md#license) | Sharing/adaptation language is qualified by the page's additional terms. Commercial consultancy use remains unresolved; retain source attribution and original third-party references. |
| SearXNG | [AGPL-3.0](https://github.com/searxng/searxng/blob/master/LICENSE); source identifies [AGPL-3.0-or-later](https://github.com/searxng/searxng/blob/master/searx/__init__.py) | Running unmodified software is permitted. Conveying copies carries notice and corresponding-source requirements. A modified network-accessible version must offer its corresponding source to remote users under section 13. |
| Ollama | [MIT](https://github.com/ollama/ollama/blob/main/LICENSE) | Preserve notices when distributing Ollama. Its MIT license does not license downloaded model weights; the documented [qwen3:8b model](https://ollama.com/library/qwen3:8b) separately lists Apache-2.0. Check each chosen model. |

Hoppscotch's backend package metadata currently says `private: true` and
`license: UNLICENSED`, while the repository root supplies MIT. This review records
the repository license and does not infer that every component of an image has
identical terms. Resolve any package-specific ambiguity before extracting or
relicensing backend code. [Backend package metadata](https://github.com/hoppscotch/hoppscotch/blob/main/packages/hoppscotch-backend/package.json).

CloudBeaver can download additional driver files. Their terms are not established
by CloudBeaver's Apache license. This review does not clear every JDBC driver or
commercial CloudBeaver edition. [Driver management](https://dbeaver.com/docs/cloudbeaver/Drivers-Management/),
[commercial-edition licensing](https://dbeaver.com/docs/cloudbeaver/How-to-Import-License/).

## Supporting projects

These are the principal project licenses, not a full container package inventory.

| Project | License or source of terms | Distribution consideration |
| --- | --- | --- |
| PostgreSQL | [PostgreSQL License](https://www.postgresql.org/about/licence/) | Preserve the specified copyright, grant, and disclaimers in copies. |
| NGINX | [BSD-style, two conditions](https://nginx.org/LICENSE) | Preserve source notices and reproduce the notices in materials supplied with binary distributions. |
| mdBook | [MPL-2.0](https://github.com/rust-lang/mdBook/blob/main/LICENSE) | Distributing covered executable code requires corresponding covered source availability. Builder binaries stay in Blacksite's build stage, but generated site assets need their own notice review. |
| mdbook-tabs | [MIT package declaration](https://docs.rs/crate/mdbook-tabs/latest/source/Cargo.toml) | The package points to [RustForWeb/mdbook-plugins](https://github.com/RustForWeb/mdbook-plugins), not a separate mdbook-tabs repository. Preserve applicable notices for copied assets. |
| Rust | [Generally MIT or Apache-2.0](https://rust-lang.org/policies/licenses/) | Consult each component's terms; the general Rust policy does not assign one license to all Cargo dependencies. |
| Alpine Linux | [Distribution of packages including musl and BusyBox](https://alpinelinux.org/about/), [package index](https://pkgs.alpinelinux.org/packages) | It has no single license covering all installed packages. Audit the actual packages before distributing an image. |
| Docker Compose | [Apache-2.0](https://github.com/docker/compose/blob/main/LICENSE) | This repository invokes an installed executable; it does not vendor Compose. Docker Desktop has separate subscription terms. |
| Podman | [Apache-2.0](https://github.com/containers/podman/blob/main/LICENSE) | Preserve relevant license/NOTICE material if distributing the executable. |
| podman-compose | [GPL-2.0-only package declaration](https://github.com/containers/podman-compose/blob/main/pyproject.toml), [license](https://github.com/containers/podman-compose/blob/main/LICENSE) | Running the separate installed command does not copy it into this repository; distributing it requires the GPL's notices/source conditions. |
| Python | [PSF License Version 2 and incorporated-software terms](https://docs.python.org/3/license.html) | Preserve the supplied notices and review incorporated components when distributing Python. |
| Pydantic | [MIT](https://github.com/pydantic/pydantic/blob/main/LICENSE) | Preserve copyright and permission notice for distributed copies. |
| SQLAlchemy | [MIT](https://github.com/sqlalchemy/sqlalchemy/blob/main/LICENSE) | Preserve copyright and permission notice for distributed copies. |
| pypdf | [BSD-3-Clause](https://github.com/py-pdf/pypdf/blob/main/LICENSE) | Preserve notices and disclaimers and do not imply author endorsement. |

Docker Desktop is separate from Docker Compose's Apache license. Docker's current
eligibility rules include free personal use and qualifying small businesses,
while larger organizations and government use can require a paid subscription.
The user's organization and subscription were not checked.
[Docker Desktop licensing](https://docs.docker.com/subscription-billing/desktop-license/).

## What the present repository does and does not establish

Blacksite supplies integration scripts, configuration, and workspace tools, while
Compose pulls the applications from their publishers. That separation is why a
single license for Blacksite cannot replace the applications' individual terms.
The current repository does not vendor their full source trees or publish their
images. This observation concerns repository contents, not whether every use of
each running application is authorized.

The service separation suggests aggregation rather than incorporation of
SearXNG into Blacksite's Python tools. That is an interpretation of the current
architecture, not a blanket exception: an upstream modification, combined work,
or actual image distribution changes the analysis. AGPL section 5 distinguishes
an aggregate of separate works from a covered combined work, and section 13
addresses modified versions used over a network.
[AGPL license text](https://github.com/searxng/searxng/blob/master/LICENSE).

Before distributing built images or an offline bundle:

- Record the exact image digests, Git commits, and build-tool versions.
- Preserve all supplied LICENSE, COPYING, COPYRIGHT, and NOTICE files, including
  dependency and browser-asset notices. A link to a moving upstream branch is not
  a substitute for license material required with a distribution.
- For copyleft components, satisfy the matching source provision applicable to
  the actual distribution method. A generic upstream homepage may be insufficient.
- Preserve upstream product branding and avoid claiming upstream endorsement.
- Clear HackTricks commercial use and any reused third-party content separately.
- Check model licenses, optional drivers, base-image packages, copied fonts,
  JavaScript, images, and other assets at their resolved versions.

mdBook's generated output can contain third-party browser assets. An upstream
issue identifies potential license-text gaps in some mdbook-html assets. This
review has not established whether that report affects Blacksite's exact image;
it is a reason to inspect the generated output before redistribution, not a
finding of a proven violation here.
[mdBook upstream issue 2956](https://github.com/rust-lang/mdBook/issues/2956).

No new license has been assigned to Blacksite's own code by this review. Existing
tool frontmatter saying MIT is not a license grant for the separate upstream
applications or downloaded content.
