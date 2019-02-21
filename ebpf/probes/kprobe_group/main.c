/*
 * Copyright (c) 2019-present Trail of Bits, Inc.
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

#include <linux/pid.h>

#define EVENTID_PIDVNR BASE_EVENT_TYPE

#define EVENTID_FORK_ENTER (BASE_EVENT_TYPE + 1U)
#define EVENTID_FORK_EXIT (BASE_EVENT_TYPE + 2U)

#define EVENTID_VFORK_ENTER (BASE_EVENT_TYPE + 3U)
#define EVENTID_VFORK_EXIT (BASE_EVENT_TYPE + 4U)

#define EVENTID_CLONE_ENTER (BASE_EVENT_TYPE + 5U)
#define EVENTID_CLONE_EXIT (BASE_EVENT_TYPE + 6U)

/// Saves namespace data into the per-cpu map
static int savePidNamespaceData(struct pid* pid) {
  int index_key = 0U;
  u64 initial_slot = 0U;
  u64* index_ptr = perf_cpu_index.lookup_or_init(&index_key, &initial_slot);
  int index = (index_ptr != NULL ? *index_ptr : initial_slot);

  u64 field = (u64)pid->level;
  perf_event_data.update(&index, &field);
  INCREMENT_EVENT_DATA_INDEX(index);

#pragma unroll
  for (int i = 0; i < 3; i++) {
    field = (u64)pid->numbers[i].nr;
    perf_event_data.update(&index, &field);
    INCREMENT_EVENT_DATA_INDEX(index);
  }

  initial_slot = index; // re-use the same var to avoid wasting stack space
  perf_cpu_index.update(&index_key, &initial_slot);

  return 0;
}

/// pid_vnr() handler
int kprobe_pid_vnr_enter(struct pt_regs* ctx, struct pid* pid) {
  if (isIgnoredProcess()) {
    return 0;
  }

  int event_index =
      saveEventHeader(EVENTID_PIDVNR, KPROBE_PIDVNR_CALL, false, 0);

  savePidNamespaceData(pid);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(ctx, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// fork() handlers
int kprobe_fork_enter(struct pt_regs* ctx, struct pid* pid) {
  if (isIgnoredProcess()) {
    return 0;
  }

  int event_index =
      saveEventHeader(EVENTID_FORK_ENTER, KPROBE_FORK_CALL, false, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(ctx, &event_identifier, sizeof(event_identifier));
  return 0;
}

int kprobe_fork_exit(struct pt_regs* ctx, struct pid* pid) {
  if (isIgnoredProcess()) {
    return 0;
  }

  int event_index = saveEventHeader(
      EVENTID_FORK_EXIT, KPROBE_FORK_CALL, true, PT_REGS_RC(ctx));

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(ctx, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// vfork() handlers
int kprobe_vfork_enter(struct pt_regs* ctx, struct pid* pid) {
  if (isIgnoredProcess()) {
    return 0;
  }

  int event_index =
      saveEventHeader(EVENTID_VFORK_ENTER, KPROBE_VFORK_CALL, false, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(ctx, &event_identifier, sizeof(event_identifier));
  return 0;
}

int kprobe_vfork_exit(struct pt_regs* ctx, struct pid* pid) {
  if (isIgnoredProcess()) {
    return 0;
  }

  int event_index = saveEventHeader(
      EVENTID_VFORK_EXIT, KPROBE_VFORK_CALL, true, PT_REGS_RC(ctx));

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(ctx, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// clone() handlers
int kprobe_clone_enter(struct pt_regs* ctx, struct pid* pid) {
  if (isIgnoredProcess()) {
    return 0;
  }

  int event_index =
      saveEventHeader(EVENTID_CLONE_ENTER, KPROBE_CLONE_CALL, false, 0);

  u64 clone_flags = 0U;
  saveEventValue(clone_flags);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(ctx, &event_identifier, sizeof(event_identifier));
  return 0;
}

int kprobe_clone_exit(struct pt_regs* ctx, struct pid* pid) {
  if (isIgnoredProcess()) {
    return 0;
  }

  int event_index = saveEventHeader(
      EVENTID_CLONE_EXIT, KPROBE_CLONE_CALL, true, PT_REGS_RC(ctx));

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(ctx, &event_identifier, sizeof(event_identifier));
  return 0;
}