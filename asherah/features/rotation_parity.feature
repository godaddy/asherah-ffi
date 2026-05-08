Feature: Cross-language rotation parity

  Verify that DRRs produced under one language binding decrypt
  correctly under another binding *after* a key rotation has occurred
  on the shared metastore. Catches FFI marshalling regressions in the
  IK / SK metadata serialization that only surface when a foreign
  language has to walk the rotated key chain.

  Background:
    Given a StaticKMS master key "746869734973415374617469634d61737465724b6579466f7254657374696e67"
    And service "rot-parity-svc" and product "rot-parity-prod" and partition "p1"

  @node
  Scenario: Rust decrypts both pre- and post-rotation DRRs encrypted by Node
    When Node encrypts payload "node-pre" with expire_after 1
    And we wait 3 seconds for IK rotation
    When Node encrypts payload "node-post" with expire_after 1
    Then Rust decrypts the pre payload and plaintext equals "node-pre"
    And Rust decrypts the post payload and plaintext equals "node-post"
    And the post DRR's IK created is strictly newer than the pre DRR's

  @node
  Scenario: Node decrypts both pre- and post-rotation DRRs encrypted by Rust
    When Rust encrypts payload "rust-pre" with expire_after 1
    And we wait 3 seconds for IK rotation
    When Rust encrypts payload "rust-post" with expire_after 1
    Then Node decrypts the pre payload and plaintext equals "rust-pre"
    And Node decrypts the post payload and plaintext equals "rust-post"
