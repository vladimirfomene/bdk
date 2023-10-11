# Wallet RPC Example 

# To run the wallet example, execute the following code (replace arguments with values that match your setup)

```
cargo run -- <RPC_URL> <RPC_USER> <RPC_PASS> <LOOKAHEAD> <FALLBACK_HEIGHT>
```

Here is the command we used during testing

```
cargo run -- 127.0.0.1:18332 bitcoin password 20 2532323
```