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

/// socket() handlers
int on_tracepoint_sys_enter_socket(
    struct tracepoint__syscalls__sys_enter_socket* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTERSOCKET, false, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  saveEventValue((u64)args->family);
  saveEventValue((u64)args->type);
  saveEventValue((u64)args->protocol);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

int on_tracepoint_sys_exit_socket(
    struct tracepoint__syscalls__sys_exit_socket* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITSOCKET, true, args->ret);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

/// socketpair() handlers
int on_tracepoint_sys_enter_socketpair(
    struct tracepoint__syscalls__sys_enter_socketpair* args) {
  int event_index = saveEventHeader(EVENTID_SYSENTERSOCKETPAIR, false, 0);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  saveEventValue((u64)args->family);
  saveEventValue((u64)args->type);
  saveEventValue((u64)args->protocol);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}

int on_tracepoint_sys_exit_socketpair(
    struct tracepoint__syscalls__sys_exit_socketpair* args) {
  int event_index = saveEventHeader(EVENTID_SYSEXITSOCKETPAIR, true, args->ret);

  u32 event_identifier =
      (((struct task_struct*)bpf_get_current_task())->cpu << 28) |
      (event_index & 0x00FFFFFF);

  events.perf_submit(args, &event_identifier, sizeof(event_identifier));
  return 0;
}
