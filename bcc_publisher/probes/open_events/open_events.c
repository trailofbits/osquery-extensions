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

/// open() handlers
int on_tracepoint_sys_enter_open(
    struct tracepoint__syscalls__sys_enter_open* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTEROPEN, false, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  char buffer[ARG_SIZE];
  saveStringFromAddress(buffer, args->filename);

  saveEventValue((u64)args->flags);
  saveEventValue((u64)args->mode);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

int on_tracepoint_sys_exit_open(
    struct tracepoint__syscalls__sys_exit_open* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITOPEN, true, args->ret);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// openat() handlers
int on_tracepoint_sys_enter_openat(
    struct tracepoint__syscalls__sys_enter_openat* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTEROPENAT, false, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  saveEventValue((u64)args->dfd);

  char buffer[ARG_SIZE];
  saveStringFromAddress(buffer, args->filename);

  saveEventValue((u64)args->flags);
  saveEventValue((u64)args->mode);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

int on_tracepoint_sys_exit_openat(
    struct tracepoint__syscalls__sys_exit_openat* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITOPENAT, true, args->ret);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// open_by_handle_at() handlers
int on_tracepoint_sys_enter_open_by_handle_at(
    struct tracepoint__syscalls__sys_enter_open_by_handle_at* args) {
  int event_index =
      saveEventHeader(EVENTID_SYSENTEROPEN_BY_HANDLE_AT, false, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  saveEventValue((u64)args->mountdirfd);
  saveEventValue((u64)args->flags);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

int on_tracepoint_sys_exit_open_by_handle_at(
    struct tracepoint__syscalls__sys_exit_open_by_handle_at* args) {
  int event_index =
      saveEventHeader(EVENTID_SYSEXITOPEN_BY_HANDLE_AT, true, args->ret);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// name_to_handle_at() handlers
int on_tracepoint_sys_enter_name_to_handle_at(
    struct tracepoint__syscalls__sys_enter_name_to_handle_at* args) {
  int event_index =
      saveEventHeader(EVENTID_SYSENTERNAME_TO_HANDLE_AT, false, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  saveEventValue((u64)args->dfd);

  char buffer[ARG_SIZE];
  saveStringFromAddress(buffer, args->name);

  saveEventValue((u64)args->mnt_id);
  saveEventValue((u64)args->flag);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

int on_tracepoint_sys_exit_name_to_handle_at(
    struct tracepoint__syscalls__sys_exit_name_to_handle_at* args) {
  int event_index =
      saveEventHeader(EVENTID_SYSEXITNAME_TO_HANDLE_AT, true, args->ret);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}
