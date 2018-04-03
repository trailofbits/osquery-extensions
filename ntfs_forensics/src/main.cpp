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



#include <iostream>

#include "ntfs_forensics.h"
#include "extension.h"

int runAsStandalone(const char *path) {
	FileInfo info;
	std::string device("\\\\.\\PhysicalDrive0");
	int rval = getFileInfo(device, std::string(path), info);
	std::cout << "rval from getFileInfo() is " << rval << std::endl;
	return rval;
}

int runAsExtension(int argc, char* argv[]) {
	std::cout << "Connecting to the running osquery instance..." << std::endl;

	osquery::Initializer runner(argc, argv, osquery::ToolType::EXTENSION);

	auto status = osquery::startExtension("ntfs", "1.0.0");
	if (!status.ok()) {
		LOG(ERROR) << status.getMessage();
		runner.requestShutdown(status.getCode());
	}

	runner.waitForShutdown();

	return 0;
}

void showUsage(char* argv[]) {
	const char* usage =
		" [--standalone <path>]\n"
		"\n"
		"\t--standalone <path>  Print info about <path>.\n"
		"\t						If not specified, it will run as an osquery extension\n";

	std::cerr << "Usage: " << argv[0] << usage;
}

int main(int argc, char* argv[]) {
	if (argc == 3 && std::strcmp(argv[1], "--standalone") == 0) {
		return runAsStandalone(argv[2]);

	}
	else if (argc == 2 && std::strcmp(argv[1], "--help") == 0) {
		showUsage(argv);
		return 0;
	}
	else {
		return runAsExtension(argc, argv);
	}
}
