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
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(exec_event_data, u64, EVENT_MAP_SIZE);
BPF_PERCPU_ARRAY(exec_cpu_index, u64, 1);

/// Saves the generic event header into the per-cpu map, returning the
/// initial index
static int saveEventHeader(u64 event_identifier,
                           BOOL save_exit_code,
                           int exit_code) {
  int index_key = 0U;
  u64 initial_slot = 0U;
  u64* index_ptr = exec_cpu_index.lookup_or_init(&index_key, &initial_slot);
  int event_index = (index_ptr != NULL ? *index_ptr : initial_slot);

  int index = event_index;
  exec_event_data.update(&index, &event_identifier);
  INCREMENT_EVENT_DATA_INDEX(index);

  u64 field = bpf_ktime_get_ns();
  exec_event_data.update(&index, &field);
  INCREMENT_EVENT_DATA_INDEX(index);

  field = bpf_get_current_pid_tgid();
  exec_event_data.update(&index, &field);
  INCREMENT_EVENT_DATA_INDEX(index);

  field = bpf_get_current_uid_gid();
  exec_event_data.update(&index, &field);
  INCREMENT_EVENT_DATA_INDEX(index);

  if (save_exit_code == TRUE) {
    field = (u64)exit_code;
    exec_event_data.update(&index, &field);
    INCREMENT_EVENT_DATA_INDEX(index);
  }

  initial_slot = index; // re-use the same var to avoid wasting stack space
  exec_cpu_index.update(&index_key, &initial_slot);

  return event_index;
}

/// Saves the given string into the per-cpu map
static BOOL saveString(const char* buffer) {
  int index_key = 0U;
  u64 initial_slot = 0U;
  u64* index_ptr = exec_cpu_index.lookup_or_init(&index_key, &initial_slot);
  int index = (index_ptr != NULL ? *index_ptr : initial_slot);

#pragma unroll
  for (int i = 0; i < ARG_SIZE / 8; i++) {
    exec_event_data.update(&index, (u64*)&buffer[i * 8]);
    INCREMENT_EVENT_DATA_INDEX(index);
  }

  initial_slot = index; // re-use the same var to avoid wasting stack space
  exec_cpu_index.update(&index_key, &initial_slot);
  return TRUE;
}

/// Saves the string pointed to by the given address into the per-cpu
/// map
static BOOL saveStringFromAddress(char* buffer, const char* address) {
  if (address == NULL) {
    return FALSE;
  }

  bpf_probe_read(buffer, ARG_SIZE, address);
  saveString(buffer);

  return TRUE;
}

/// Saves the truncation identifier into the per-cpu map; used for varargs
/// functions likes execve
static BOOL emitVarargsTerminator(BOOL truncated) {
  int index_key = 0U;
  u64 initial_slot = 0U;
  u64* index_ptr = exec_cpu_index.lookup_or_init(&index_key, &initial_slot);
  int index = (index_ptr != NULL ? *index_ptr : initial_slot);

  u64 terminator = truncated == TRUE ? VARARGS_TRUNCATION : VARARGS_TERMINATOR;
  exec_event_data.update(&index, &terminator);
  INCREMENT_EVENT_DATA_INDEX(index);

  initial_slot = index; // re-use the same var to avoid wasting stack space
  exec_cpu_index.update(&index_key, &initial_slot);
  return TRUE;
}

/// Execve handlers
int on_tracepoint_sys_enter_execve(
    struct tracepoint__syscalls__sys_enter_execve* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTEREXECVE, FALSE, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  char buffer[ARG_SIZE];
  const char* argument_ptr = NULL;

  saveStringFromAddress(buffer, args->filename);

#pragma unroll
  for (int i = 1; i < MAX_ARGS; i++) {
    bpf_probe_read(&argument_ptr, sizeof(argument_ptr), &args->argv[i]);
    if (saveStringFromAddress(buffer, argument_ptr) == FALSE) {
      goto emit_terminator;
    }
  }

  goto emit_truncation;

emit_truncation:
  emitVarargsTerminator(TRUE);
  goto emit_event;

emit_terminator:
  emitVarargsTerminator(FALSE);
  goto emit_event;

emit_event:
  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

int on_tracepoint_sys_exit_execve(
    struct tracepoint__syscalls__sys_exit_execve* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITEXECVE, TRUE, args->ret);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// Execveat handlers
int on_tracepoint_sys_enter_execveat(
    struct tracepoint__syscalls__sys_enter_execveat* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTEREXECVEAT, FALSE, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  char buffer[ARG_SIZE];
  const char* argument_ptr = NULL;

  saveStringFromAddress(buffer, args->filename);

#pragma unroll
  for (int i = 1; i < MAX_ARGS; i++) {
    bpf_probe_read(&argument_ptr, sizeof(argument_ptr), &args->argv[i]);
    if (saveStringFromAddress(buffer, argument_ptr) == FALSE) {
      goto emit_terminator;
    }
  }

  goto emit_truncation;

emit_truncation:
  emitVarargsTerminator(TRUE);
  goto emit_event;

emit_terminator:
  emitVarargsTerminator(FALSE);
  goto emit_event;

emit_event:
  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

int on_tracepoint_sys_exit_execveat(
    struct tracepoint__syscalls__sys_exit_execveat* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITEXECVEAT, TRUE, args->ret);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}
