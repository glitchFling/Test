(module
  ;; ------------------------------------------------------------
  ;; IMPORTS (must come first)
  ;; ------------------------------------------------------------
  (import "env" "hash32"
    (func $hash32 (param i32 i32 i32 i32 i32)))

  ;; ------------------------------------------------------------
  ;; MEMORY + GLOBALS
  ;; ------------------------------------------------------------
  (memory (export "memory") 1024) ;; 64 MiB
  (global $block_size (mut i32) (i32.const 32))
  (global $max_blocks (mut i32) (i32.const 2097152))

  ;; ------------------------------------------------------------
  ;; CONSTANT‑TIME COMPARE
  ;; ------------------------------------------------------------
  (func (export "ct_eq")
    (param $a i32) (param $b i32) (param $len i32)
    (result i32)
    (local $i i32) (local $acc i32)

    (local.set $i (i32.const 0))
    (local.set $acc (i32.const 0))

    (loop $loop
      (br_if $loop
        (i32.lt_u (local.get $i) (local.get $len)))

      (local.set $acc
        (i32.or
          (local.get $acc)
          (i32.xor
            (i32.load8_u (i32.add (local.get $a) (local.get $i)))
            (i32.load8_u (i32.add (local.get $b) (local.get $i))))))

      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $loop)
    )

    (i32.eqz (local.get $acc))
  )

  ;; ------------------------------------------------------------
  ;; MEMORY‑HARD KDF ENTRYPOINT (stub)
  ;; ------------------------------------------------------------
  (func (export "derive_key")
    (param $pwd i32) (param $pwd_len i32)
    (param $salt i32) (param $salt_len i32)
    (param $out i32)
    (param $blocks i32) (param $passes i32)

    ;; TODO: insert your memory-hard loop here
    ;; This stub just calls hash32 so the module compiles.
    (call $hash32
      (local.get $pwd)
      (local.get $pwd_len)
      (local.get $salt)
      (local.get $salt_len)
      (local.get $out))
  )

  ;; ------------------------------------------------------------
  ;; VERIFY
  ;; ------------------------------------------------------------
  (func (export "verify")
    (param $pwd i32) (param $pwd_len i32)
    (param $salt i32) (param $salt_len i32)
    (param $expected i32)
    (param $blocks i32) (param $passes i32)
    (result i32)

    (local $tmp i32)
    (local.set $tmp (i32.const 4096))

    (call $derive_key
      (local.get $pwd)
      (local.get $pwd_len)
      (local.get $salt)
      (local.get $salt_len)
      (local.get $tmp)
      (local.get $blocks)
      (local.get $passes))

    (call $ct_eq
      (local.get $tmp)
      (local.get $expected)
      (i32.const 32))
  )
)
