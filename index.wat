(module
  ;; 64 MiB linear memory for memory-hardness (1024 * 64 KiB)
  (memory (export "memory") 1024)

  ;; --- Imports --------------------------------------------------------------
  ;; env.hash32(p_in, in_len, p_salt, salt_len, p_out)
  ;;   -> writes 32-byte hash to p_out
  (import "env" "hash32"
    (func $hash32 (param i32 i32 i32 i32 i32)))

  ;; --- Constants ------------------------------------------------------------
  (global $block_size (mut i32) (i32.const 32))        ;; 32 bytes per block
  (global $mem_bytes (mut i32) (i32.const 67108864))   ;; 64 MiB
  (global $max_blocks (mut i32) (i32.const 2097152))   ;; 64 MiB / 32

  ;; --- Helpers --------------------------------------------------------------

  ;; ct_eq(a_ptr, b_ptr, len) -> i32 (1 == equal, 0 == not equal)
  (func (export "ct_eq") (param $a i32) (param $b i32) (param $len i32) (result i32)
    (local $i i32)
    (local $acc i32)
    (local $va i32)
    (local $vb i32)

    (local.set $i (i32.const 0))
    (local.set $acc (i32.const 0))

    (block $exit
      (loop $loop
        (br_if $exit (i32.ge_u (local.get $i) (local.get $len)))

        (local.set $va
          (i32.load8_u (i32.add (local.get $a) (local.get $i))))
        (local.set $vb
          (i32.load8_u (i32.add (local.get $b) (local.get $i))))

        (local.set $acc
          (i32.or
            (local.get $acc)
            (i32.xor (local.get $va) (local.get $vb))))

        (local.set $i
          (i32.add (local.get $i) (i32.const 1)))
        (br $loop)
      )
    )

    (return
      (i32.eqz (local.get $acc)))
  )

  ;; --- Memory-hard KDF core -------------------------------------------------
  ;;
  ;; derive_key(p_pwd, pwd_len, p_salt, salt_len,
  ;;            p_out, blocks, passes)
  ;;
  ;; - blocks: number of 32-byte blocks to use (clamped to max_blocks)
  ;; - passes: number of full sweeps over memory
  ;;
  ;; Layout:
  ;;   region_base = 0
  ;;   block i at: region_base + i * 32
  ;;
  ;; Block fill:
  ;;   B[0] = H(pwd || salt)
  ;;   For i in [1..blocks-1]:
  ;;     idx = (B[i-1][0..3] as u32) mod i
  ;;     tmp = B[i-1] XOR B[idx]
  ;;     B[i] = H(tmp || salt)
  ;;
  ;; Additional passes:
  ;;   For pass in [1..passes-1]:
  ;;     For i in [0..blocks-1]:
  ;;       idx = (B[i][4..7] as u32) mod blocks
  ;;       tmp = B[i] XOR B[idx]
  ;;       B[i] = H(tmp || salt)
  ;;
  ;; Output:
  ;;   out = H(B[blocks-1] || salt)
  ;;
  (func (export "derive_key")
    (param $p_pwd i32)    ;; 0
    (param $pwd_len i32)  ;; 1
    (param $p_salt i32)   ;; 2
    (param $salt_len i32) ;; 3
    (param $p_out i32)    ;; 4
    (param $blocks i32)   ;; 5
    (param $passes i32)   ;; 6
  )
    (local $region_base i32)
    (local $max_blocks_local i32)
    (local $i i32)
    (local $pass i32)
    (local $idx i32)
    (local $tmp_ptr i32)
    (local $cur_ptr i32)
    (local $prev_ptr i32)
    (local $idx_ptr i32)
    (local $bs i32)
    (local $in_ptr i32)
    (local $in_len i32)
    (local $word i32)

    ;; block size
    (local.set $bs (global.get $block_size))
    (local.set $region_base (i32.const 0))
    (local.set $max_blocks_local (global.get $max_blocks))

    ;; clamp blocks to [2, max_blocks]
    (if (i32.lt_s (local.get $blocks) (i32.const 2))
      (then (local.set $blocks (i32.const 2))))
    (if (i32.gt_u (local.get $blocks) (local.get $max_blocks_local))
      (then (local.set $blocks (local.get $max_blocks_local))))

    ;; tmp buffer right after region: tmp = region_base + blocks * bs
    (local.set $tmp_ptr
      (i32.mul (local.get $blocks) (local.get $bs)))

    ;; --- B[0] = H(pwd || salt) ---------------------------------------------
    ;; We reuse tmp buffer as input concat: [pwd][salt]
    (local.set $in_ptr (local.get $tmp_ptr))

    ;; copy pwd
    (local.set $i (i32.const 0))
    (block $exit_pwd
      (loop $loop_pwd
        (br_if $exit_pwd (i32.ge_u (local.get $i) (local.get $pwd_len)))
        (i32.store8
          (i32.add (local.get $in_ptr) (local.get $i))
          (i32.load8_u
            (i32.add (local.get $p_pwd) (local.get $i))))
        (local.set $i
          (i32.add (local.get $i) (i32.const 1)))
        (br $loop_pwd)
      )
    )

    ;; copy salt
    (local.set $i (i32.const 0))
    (block $exit_salt
      (loop $loop_salt
        (br_if $exit_salt (i32.ge_u (local.get $i) (local.get $salt_len)))
        (i32.store8
          (i32.add
            (local.get $in_ptr)
            (i32.add (local.get $pwd_len) (local.get $i)))
          (i32.load8_u
            (i32.add (local.get $p_salt) (local.get $i))))
        (local.set $i
          (i32.add (local.get $i) (i32.const 1)))
        (br $loop_salt)
      )
    )

    (local.set $in_len
      (i32.add (local.get $pwd_len) (local.get $salt_len)))

    ;; hash32(in_ptr, in_len, p_salt, salt_len, B[0])
    (call $hash32
      (local.get $in_ptr)
      (local.get $in_len)
      (local.get $p_salt)
      (local.get $salt_len)
      (local.get $region_base))

    ;; --- First pass: sequential fill with indexed mixing --------------------
    (local.set $i (i32.const 1))
    (block $exit_first
      (loop $loop_first
        (br_if $exit_first (i32.ge_u (local.get $i) (local.get $blocks)))

        ;; prev_ptr = B[i-1]
        (local.set $prev_ptr
          (i32.add
            (local.get $region_base)
            (i32.mul
              (i32.sub (local.get $i) (i32.const 1))
              (local.get $bs))))

        ;; idx = (u32)load32(prev_ptr) % i
        (local.set $word
          (i32.load (local.get $prev_ptr)))
        (local.set $idx
          (i32.rem_u (local.get $word) (local.get $i)))

        ;; idx_ptr = B[idx]
        (local.set $idx_ptr
          (i32.add
            (local.get $region_base)
            (i32.mul (local.get $idx) (local.get $bs))))

        ;; tmp = B[i-1] XOR B[idx]
        (local.set $cur_ptr (local.get $tmp_ptr))
        (local.set $word (i32.const 0))
        (local.set $in_len (local.get $bs))

        (local.set $word (i32.const 0))
        (block $exit_xor0
          (loop $loop_xor0
            (br_if $exit_xor0
              (i32.ge_u (local.get $word) (local.get $bs)))

            (i32.store8
              (i32.add (local.get $cur_ptr) (local.get $word))
              (i32.xor
                (i32.load8_u
                  (i32.add (local.get $prev_ptr) (local.get $word)))
                (i32.load8_u
                  (i32.add (local.get $idx_ptr) (local.get $word)))))

            (local.set $word
              (i32.add (local.get $word) (i32.const 1)))
            (br $loop_xor0)
          )
        )

        ;; input = tmp || salt
        ;; copy salt after tmp
        (local.set $in_ptr (local.get $cur_ptr))
        (local.set $i
          (local.get $i)) ;; keep i

        (local.set $word (i32.const 0))
        (block $exit_salt2
          (loop $loop_salt2
            (br_if $exit_salt2
              (i32.ge_u (local.get $word) (local.get $salt_len)))
            (i32.store8
              (i32.add
                (local.get $in_ptr)
                (i32.add (local.get $bs) (local.get $word)))
              (i32.load8_u
                (i32.add (local.get $p_salt) (local.get $word))))
            (local.set $word
              (i32.add (local.get $word) (i32.const 1)))
            (br $loop_salt2)
          )
        )

        (local.set $in_len
          (i32.add (local.get $bs) (local.get $salt_len)))

        ;; B[i] = H(tmp || salt)
        (local.set $cur_ptr
          (i32.add
            (local.get $region_base)
            (i32.mul (local.get $i) (local.get $bs))))

        (call $hash32
          (local.get $in_ptr)
          (local.get $in_len)
          (local.get $p_salt)
          (local.get $salt_len)
          (local.get $cur_ptr))

        (local.set $i
          (i32.add (local.get $i) (i32.const 1)))
        (br $loop_first)
      )
    )

    ;; --- Additional passes --------------------------------------------------
    (local.set $pass (i32.const 1))
    (block $exit_passes
      (loop $loop_passes
        (br_if $exit_passes
          (i32.ge_u (local.get $pass) (local.get $passes)))

        (local.set $i (i32.const 0))
        (block $exit_inner
          (loop $loop_inner
            (br_if $exit_inner
              (i32.ge_u (local.get $i) (local.get $blocks)))

            ;; cur_ptr = B[i]
            (local.set $cur_ptr
              (i32.add
                (local.get $region_base)
                (i32.mul (local.get $i) (local.get $bs))))

            ;; idx = (u32)load32(cur_ptr+4) % blocks
            (local.set $word
              (i32.load
                (i32.add (local.get $cur_ptr) (i32.const 4))))
            (local.set $idx
              (i32.rem_u (local.get $word) (local.get $blocks)))

            ;; idx_ptr = B[idx]
            (local.set $idx_ptr
              (i32.add
                (local.get $region_base)
                (i32.mul (local.get $idx) (local.get $bs))))

            ;; tmp = B[i] XOR B[idx]
            (local.set $word (i32.const 0))
            (block $exit_xor1
              (loop $loop_xor1
                (br_if $exit_xor1
                  (i32.ge_u (local.get $word) (local.get $bs)))

                (i32.store8
                  (i32.add (local.get $tmp_ptr) (local.get $word))
                  (i32.xor
                    (i32.load8_u
                      (i32.add (local.get $cur_ptr) (local.get $word)))
                    (i32.load8_u
                      (i32.add (local.get $idx_ptr) (local.get $word)))))

                (local.set $word
                  (i32.add (local.get $word) (i32.const 1)))
                (br $loop_xor1)
              )
            )

            ;; input = tmp || salt
            (local.set $in_ptr (local.get $tmp_ptr))
            (local.set $word (i32.const 0))
            (block $exit_salt3
              (loop $loop_salt3
                (br_if $exit_salt3
                  (i32.ge_u (local.get $word) (local.get $salt_len)))
                (i32.store8
                  (i32.add
                    (local.get $in_ptr)
                    (i32.add (local.get $bs) (local.get $word)))
                  (i32.load8_u
                    (i32.add (local.get $p_salt) (local.get $word))))
                (local.set $word
                  (i32.add (local.get $word) (i32.const 1)))
                (br $loop_salt3)
              )
            )

            (local.set $in_len
              (i32.add (local.get $bs) (local.get $salt_len)))

            ;; B[i] = H(tmp || salt)
            (call $hash32
              (local.get $in_ptr)
              (local.get $in_len)
              (local.get $p_salt)
              (local.get $salt_len)
              (local.get $cur_ptr))

            (local.set $i
              (i32.add (local.get $i) (i32.const 1)))
            (br $loop_inner)
          )
        )

        (local.set $pass
          (i32.add (local.get $pass) (i32.const 1)))
        (br $loop_passes)
      )
    )

    ;; --- Final output: H(B[blocks-1] || salt) -------------------------------
    (local.set $cur_ptr
      (i32.add
        (local.get $region_base)
        (i32.mul
          (i32.sub (local.get $blocks) (i32.const 1))
          (local.get $bs))))

    ;; tmp = B[last] || salt
    (local.set $in_ptr (local.get $tmp_ptr))
    (local.set $word (i32.const 0))
    (block $exit_copy_last
      (loop $loop_copy_last
        (br_if $exit_copy_last
          (i32.ge_u (local.get $word) (local.get $bs)))
        (i32.store8
          (i32.add (local.get $in_ptr) (local.get $word))
          (i32.load8_u
            (i32.add (local.get $cur_ptr) (local.get $word))))
        (local.set $word
          (i32.add (local.get $word) (i32.const 1)))
        (br $loop_copy_last)
      )
    )

    (local.set $word (i32.const 0))
    (block $exit_salt4
      (loop $loop_salt4
        (br_if $exit_salt4
          (i32.ge_u (local.get $word) (local.get $salt_len)))
        (i32.store8
          (i32.add
            (local.get $in_ptr)
            (i32.add (local.get $bs) (local.get $word)))
          (i32.load8_u
            (i32.add (local.get $p_salt) (local.get $word))))
        (local.set $word
          (i32.add (local.get $word) (i32.const 1)))
        (br $loop_salt4)
      )
    )

    (local.set $in_len
      (i32.add (local.get $bs) (local.get $salt_len)))

    (call $hash32
      (local.get $in_ptr)
      (local.get $in_len)
      (local.get $p_salt)
      (local.get $salt_len)
      (local.get $p_out))
  )

  ;; verify(p_pwd, pwd_len, p_salt, salt_len,
  ;;        p_expected, blocks, passes) -> i32
  ;;   1 == ok, 0 == fail
  (func (export "verify")
    (param $p_pwd i32)
    (param $pwd_len i32)
    (param $p_salt i32)
    (param $salt_len i32)
    (param $p_expected i32)
    (param $blocks i32)
    (param $passes i32)
    (result i32)
    (local $p_out i32)

    ;; place derived key at end of first block (just an arbitrary offset)
    (local.set $p_out
      (i32.add (i32.const 0) (i32.const 4096)))

    (call $derive_key
      (local.get $p_pwd)
      (local.get $pwd_len)
      (local.get $p_salt)
      (local.get $salt_len)
      (local.get $p_out)
      (local.get $blocks)
      (local.get $passes))

    (return
      (call $ct_eq
        (local.get $p_out)
        (local.get $p_expected)
        (i32.const 32)))
  )
)
