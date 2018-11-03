/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <linux/fs.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(fork_event_data, u64, EVENT_MAP_SIZE);
BPF_PERCPU_ARRAY(fork_cpu_index, u64, 1);

/// Saves the generic event header into the per-cpu map, returning the
/// initial index
static int saveEventHeader(u64 event_identifier) {
  int index_key = 0U;
  u64 initial_slot = 0U;
  u64* index_ptr = fork_cpu_index.lookup_or_init(&index_key, &initial_slot);
  int event_index = (index_ptr != NULL ? *index_ptr : initial_slot);

  int index = event_index;
  fork_event_data.update(&index, &event_identifier);
  INCREMENT_EVENT_DATA_INDEX(index);

  u64 field = bpf_ktime_get_ns();
  fork_event_data.update(&index, &field);
  INCREMENT_EVENT_DATA_INDEX(index);

  field = bpf_get_current_pid_tgid();
  fork_event_data.update(&index, &field);
  INCREMENT_EVENT_DATA_INDEX(index);

  field = bpf_get_current_uid_gid();
  fork_event_data.update(&index, &field);
  INCREMENT_EVENT_DATA_INDEX(index);

  initial_slot = index; // re-use the same var to avoid wasting stack space
  fork_cpu_index.update(&index_key, &initial_slot);

  return event_index;
}

/// Saves namespace data into the per-cpu map
static BOOL savePidNamespaceData(struct pid* pid) {
  int index_key = 0U;
  u64 initial_slot = 0U;
  u64* index_ptr = fork_cpu_index.lookup_or_init(&index_key, &initial_slot);
  int index = (index_ptr != NULL ? *index_ptr : initial_slot);

  u64 field = (u64)pid->level;
  fork_event_data.update(&index, &field);
  INCREMENT_EVENT_DATA_INDEX(index);

#pragma unroll
  for (int i = 0; i < 3; i++) {
    field = (u64)pid->numbers[i].nr;
    fork_event_data.update(&index, &field);
    INCREMENT_EVENT_DATA_INDEX(index);
  }

  initial_slot = index; // re-use the same var to avoid wasting stack space
  fork_cpu_index.update(&index_key, &initial_slot);

  return TRUE;
}

/// clone() handler
int on_tracepoint_sys_enter_clone(
    struct tracepoint__syscalls__sys_enter_clone* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTERCLONE);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// clone() handler
int on_tracepoint_sys_exit_clone(
    struct tracepoint__syscalls__sys_exit_clone* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITCLONE);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// fork() handler
int on_tracepoint_sys_enter_fork(
    struct tracepoint__syscalls__sys_enter_fork* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTERFORK);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// fork() handler
int on_tracepoint_sys_exit_fork(
    struct tracepoint__syscalls__sys_exit_fork* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITFORK);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// vfork() handler
int on_tracepoint_sys_enter_vfork(
    struct tracepoint__syscalls__sys_enter_vfork* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTERVFORK);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// vfork() handler
int on_tracepoint_sys_exit_vfork(
    struct tracepoint__syscalls__sys_exit_vfork* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITVFORK);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// pid_vnr() handler
int on_kprobe_pid_vnr_enter(struct pt_regs* ctx, struct pid* pid) {
  int event_index = saveEventHeader(EVENTID_PIDVNR);
  savePidNamespaceData(pid);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(ctx, &event_identifier, sizeof(event_identifier));
  return 0;
}
