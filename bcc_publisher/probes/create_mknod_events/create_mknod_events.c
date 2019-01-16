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

/// creat() handlers
int on_tracepoint_sys_enter_creat(
    struct tracepoint__syscalls__sys_enter_creat* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTERCREAT, false, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  char buffer[ARG_SIZE];
  saveStringFromAddress(buffer, args->pathname);

  saveEventValue((u64)args->mode);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

int on_tracepoint_sys_exit_creat(
    struct tracepoint__syscalls__sys_exit_creat* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITCREAT, true, args->ret);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// mknod() handlers
int on_tracepoint_sys_enter_mknod(
    struct tracepoint__syscalls__sys_enter_mknod* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTERMKNOD, false, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  char buffer[ARG_SIZE];
  saveStringFromAddress(buffer, args->filename);

  saveEventValue((u64)args->mode);
  saveEventValue((u64)args->dev);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

int on_tracepoint_sys_exit_mknod(
    struct tracepoint__syscalls__sys_exit_mknod* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITMKNOD, true, args->ret);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// mknodat() handlers
int on_tracepoint_sys_enter_mknodat(
    struct tracepoint__syscalls__sys_enter_mknodat* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTERMKNODAT, false, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  saveEventValue((u64)args->dfd);

  char buffer[ARG_SIZE];
  saveStringFromAddress(buffer, args->filename);

  saveEventValue((u64)args->mode);
  saveEventValue((u64)args->dev);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

int on_tracepoint_sys_exit_mknodat(
    struct tracepoint__syscalls__sys_exit_mknodat* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITMKNODAT, true, args->ret);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}
