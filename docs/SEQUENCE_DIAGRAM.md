# SEQUENCE_DIAGRAM (opening slide)
`docs/sequence_diagram.svg` (insert into PowerPoint: Insert > Pictures; SVG is supported) is generated with the real message sizes of the reconstructed configuration (M1 416 bits, M2 608 bits; 576 with the paper's 32-bit timestamp).
The same picture is drawn live on page 1 of the dashboard, with sizes for the configuration you select.

Mermaid version (paste into draw.io: Arrange > Insert > Advanced > Mermaid, or into mermaid.live):
```mermaid
sequenceDiagram
    participant S as 6LN (sensor)
    participant C as 6LC (controller)
    Note over S,C: 0. Registration (once, secure channel)
    S->>C: M1 = T6LN | D | CT | Tag6LN | RN1  (416 bits)
    Note right of C: AKE2: freshness, alias, tag, RN1, Sc' checks; derive SK; M = SHA-1(SK)
    C->>S: M2 = T6C | A1 | M | CT1 | Tag6LC | RN2  (608 bits reconstructed / 576 literal)
    Note left of S: AKE3: freshness, A1, tag, M check; derive the SAME SK
    Note over S,C: SK exists on both sides and is never transmitted
```
