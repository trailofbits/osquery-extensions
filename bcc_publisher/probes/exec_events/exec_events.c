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

/// Execve handlers
int on_tracepoint_sys_enter_execve(
    struct tracepoint__syscalls__sys_enter_execve* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTEREXECVE, false, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  char buffer[ARG_SIZE];
  const char* argument_ptr = NULL;

  saveStringFromAddress(buffer, args->filename);

#pragma unroll
  for (int i = 1; i < MAX_ARGS; i++) {
    bpf_probe_read(&argument_ptr, sizeof(argument_ptr), &args->argv[i]);
    if (saveStringFromAddress(buffer, argument_ptr) == false) {
      goto emit_terminator;
    }
  }

  goto emit_truncation;

emit_truncation:
  emitVarargsTerminator(true);
  goto emit_event;

emit_terminator:
  emitVarargsTerminator(false);
  goto emit_event;

emit_event:
  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

int on_tracepoint_sys_exit_execve(
    struct tracepoint__syscalls__sys_exit_execve* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITEXECVE, true, args->ret);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// Execveat handlers
int on_tracepoint_sys_enter_execveat(
    struct tracepoint__syscalls__sys_enter_execveat* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTEREXECVEAT, false, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  char buffer[ARG_SIZE];
  const char* argument_ptr = NULL;

  saveStringFromAddress(buffer, args->filename);

#pragma unroll
  for (int i = 1; i < MAX_ARGS; i++) {
    bpf_probe_read(&argument_ptr, sizeof(argument_ptr), &args->argv[i]);
    if (saveStringFromAddress(buffer, argument_ptr) == false) {
      goto emit_terminator;
    }
  }

  goto emit_truncation;

emit_truncation:
  emitVarargsTerminator(true);
  goto emit_event;

emit_terminator:
  emitVarargsTerminator(false);
  goto emit_event;

emit_event:
  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

int on_tracepoint_sys_exit_execveat(
    struct tracepoint__syscalls__sys_exit_execveat* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITEXECVEAT, true, args->ret);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}
