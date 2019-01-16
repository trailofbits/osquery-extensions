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

/// close() handlers
int on_tracepoint_sys_enter_close(
    struct tracepoint__syscalls__sys_enter_close* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTERCLOSE, false, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  saveEventValue((u64)args->fd);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

int on_tracepoint_sys_exit_close(
    struct tracepoint__syscalls__sys_exit_close* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITCLOSE, true, args->ret);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// dup() handlers
int on_tracepoint_sys_enter_dup(
    struct tracepoint__syscalls__sys_enter_dup* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTERDUP, false, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  saveEventValue((u64)args->fildes);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

int on_tracepoint_sys_exit_dup(
    struct tracepoint__syscalls__sys_exit_dup* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITDUP, true, args->ret);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// dup2() handlers
int on_tracepoint_sys_enter_dup2(
    struct tracepoint__syscalls__sys_enter_dup2* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTERDUP2, false, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  saveEventValue((u64)args->oldfd);
  saveEventValue((u64)args->newfd);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

int on_tracepoint_sys_exit_dup2(
    struct tracepoint__syscalls__sys_exit_dup2* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITDUP2, true, args->ret);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// dup3() handlers
int on_tracepoint_sys_enter_dup3(
    struct tracepoint__syscalls__sys_enter_dup3* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTERDUP3, false, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  saveEventValue((u64)args->oldfd);
  saveEventValue((u64)args->newfd);
  saveEventValue((u64)args->flags);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

int on_tracepoint_sys_exit_dup3(
    struct tracepoint__syscalls__sys_exit_dup3* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITDUP3, true, args->ret);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}
