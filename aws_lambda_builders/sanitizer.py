"""
Sanitizer of Workflows
"""

import functools
import logging

from aws_lambda_builders.exceptions import WorkflowFailedError, MisMatchRuntimeError

LOG = logging.getLogger(__name__)

class Sanitizer(object):

    def __init__(self, binaries, workflow_name, func=None):
        self.valid_paths = {}
        self.invalid_paths = {}
        self.func = func
        self.binaries = binaries
        self.workflow_name = workflow_name
        # for binary_name, _ in self.binaries:
        #     self.invalid_paths[binary_name] = []

    def __call__(self, *args, **kwargs):
        import ipdb
        ipdb.set_trace()
    def resolved_paths(self, binary_checker):
        try:
            return binary_checker.resolver.exec_paths if not binary_checker.path_provided else binary_checker.binary_path
        except ValueError as ex:
            raise WorkflowFailedError(workflow_name=self.workflow_name, action_name="Resolver", reason=str(ex))

    def validate_path(self, binary_name, binary_checker, executable_path):
       try:
            valid_path = binary_checker.validator.validate(executable_path)
            if valid_path:
                self.valid_paths[binary_name] = valid_path
       except MisMatchRuntimeError as ex:
           LOG.debug("Invalid executable for %s at %s", binary_name, executable_path, exc_info=str(ex))
           self.invalid_paths[binary_name].append(executable_path)

    def check_valid_workflow(self):
        if len(self.binaries) != len(self.valid_paths):
            validation_failed_binaries = set(self.binaries.keys()).difference(self.valid_paths.keys())

            messages = []
            for validation_failed_binary in validation_failed_binaries:
                message = "Binary validation failed for {0}, searched for {0} in following locations  : {1} which did not satisfy constraints".format(
                    validation_failed_binary, self.invalid_paths[validation_failed_binary]
                )
                messages.append(message)

            raise WorkflowFailedError(workflow_name=self.workflow_name, action_name="Validation", reason="\n".join(messages))

    def sanitize(self, func):
        """
        sanitize the executables that are required for a workflow by resolving and validating them.
        """
        @functools.wraps(func)
        def sanitize_wrapper(self, *args, **kwargs):
            for binary_name, binary_checker in self.binaries.items():
                for executable_path in self.resolved_paths(binary_checker):
                    self.validate_path(binary_name, binary_checker, executable_path)
                    if self.valid_paths.get(binary_name, None):
                        binary_checker.binary_path = self.valid_paths
                        break
            self.check_valid_workflow()

            func(self, *args, **kwargs)

        return sanitize_wrapper




