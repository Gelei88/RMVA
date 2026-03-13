# rust-mmap-virtual-arena

**OS 虚拟内存 + 需求分页优化的 Rust Arena 分配器**（灵感来源 emoon）

## 简介
用 `mmap(MAP_ANON | PROT_NONE)` 一次性预留几 GB 虚拟地址空间，按需 `mprotect` commit 物理页面 + bump 指针分配。  
- 零碎片  
- 释放 O(1)（rewind）  
- 比 std::alloc 快 3-5x（高吞吐后端场景）

## 核心原理（OS 深度）
ELF 执行开始 (execve syscall)
          ↓
内核加载 ELF 段 + 初始化 VA 空间 + brk heap
          ↓
用户 main() 开始运行
          ├──────────────────────────────┬──────────────────────────────────────┐
          │ 标准库 malloc / Vec::push     │  emoon/arena-allocator (本项目)     │
          └──────────────────────────────┴──────────────────────────────────────┘

标准库路径：
1. malloc(4KB) → glibc malloc → syscall brk/mmap 小块
2. 每次 → 可能锁 + 找 free list + syscall
3. 物理页立即 commit（malloc 内部已 touch）
4. 释放 free() → 还给 glibc pool 或 munmap

Arena 路径（核心优化点）：
1. Arena::new() → reserve_range()
   → mmap(1GB, PROT_NONE, ANON)          ← 只 VMA + 顶级 page table
   → 零物理内存！零 page fault！

2. alloc_array(1M u32) → bump pos
   → 如果跨页：commit_memory()
      → mprotect(当前页, PROT_RW)        ← 更新 VMA 权限

3. *slice[i] = val（第一次写） → CPU page fault！
   → 内核 do_pagefault() 
      → 分配物理 RAM + 填 PTE 第4级
      → 更新 TLB 快表
   → 以后同一页全走 TLB（用户态）

4. rewind() 
   → pos = 0
   → debug: mprotect(整个范围, PROT_NONE) ← 旧指针立刻 SIGSEGV

