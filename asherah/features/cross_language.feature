Feature: Cross-language compatibility with Node Asherah

  Background:
    Given a StaticKMS master key "746869734973415374617469634d61737465724b6579466f7254657374696e67"
    And service "svc" and product "prod" and partition "p1"

  @node
  Scenario: Decrypt payload encrypted by Node Asherah
    When Node encrypts payload "hello-cross" using the same config
    Then Rust decrypts it successfully and plaintext equals "hello-cross"

  @node
  Scenario: Node decrypts payload encrypted by Rust
    When Rust encrypts payload "rust-to-node"
    Then Node decrypts it successfully and plaintext equals "rust-to-node"
