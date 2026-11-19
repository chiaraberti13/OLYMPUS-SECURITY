# Accessibility

## Scope and verification status

CLI, TUI and reports. Check text feedback, operation without colour and navigation of interactive views.

Accessibility is an ongoing objective. Automated checks do not replace manual assessment with assistive technology. This statement does not certify WCAG conformance. Lack of reported issues does not establish the absence of barriers.

The Chromium job audits all 26 declared HTML GET pages, including the
finding, engagement and job details, plus two missing-resource responses.
At 320 and 1280 CSS pixels it checks the expected status and heading, runs
axe-core and checks horizontal reflow. A route inventory test flags new HTML
GET pages missing from the audit matrix. The `browser-accessibility` artifact
records the passed rules, violations and inconclusive checks for each case.
Separate tests cover keyboard sign-in, the skip link, recovery after a rejected login and offline indicator extraction in Metis. Other form submissions,
all possible data states and assistive-technology usability require separate
evidence.

## Environments and limitations

See the [README](README.md) for runtime requirements. Runtime support does not imply compatibility with every assistive technology. Record browser, operating system, screen reader or terminal versions when testing. Third-party components and exported documents require separate assessment.

## Report a barrier

Open an [accessibility issue](https://github.com/chiaraberti13/OLYMPUS-SECURITY/issues/new?template=accessibility.yml) with the task, steps, expected result and environment, including assistive technology if used. No diagnosis or health information is required. Use examples without personal data. Follow the [security policy](SECURITY.md) for sensitive reports.

## Contribution expectations

- Check keyboard access, focus order and visible focus where applicable.
- Provide clear labels, understandable errors and text alternatives for meaningful images and charts.
- Do not communicate essential information through colour, sound or motion alone.
- Check zoom and readability and respect reduced-motion preferences where applicable.
- Record steps, versions, outcomes and limitations, distinguishing automated and manual checks.

The maintainer coordinates reports and updates this statement as evidence changes. Barriers preventing essential tasks receive priority.
