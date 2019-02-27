import os
import yaml
from requests import get

from Tests.test_utils import print_error, get_json, CONTENT_GIT_HUB_LINK


class IntegrationValidator(object):
    """IntegrationValidator is designed to validate the correctness of the file structure we enter to content repo. And
    also try to catch possible Backward compatibility breaks due to the preformed changes.

    Attributes:
       _is_valid (bool): the attribute which saves the valid/in-valid status of the current file.
       file_path (str): the path to the file we are examining at the moment.
       current_integration (dict): Json representation of the current integration from the branch.
       old_integration (dict): Json representation of the current integration from master.
    """
    def __init__(self, file_path, check_git=True):
        self._is_valid = True

        self.file_path = file_path
        if check_git:
            self.current_integration = get_json(file_path)
            self.old_integration = yaml.load(get(os.path.join(CONTENT_GIT_HUB_LINK, file_path)).content)

    def is_backward_compatible(self):
        """Check whether the Integration is backward compatible or not, update the _is_valid field to determine that"""
        self.is_changed_context_path()
        self.is_docker_image_changed()
        self.is_added_required_fields()
        self.is_changed_command_name_or_arg()

        return self._is_valid

    def _get_command_to_args(self, integration_json):
        """Get a dictionary command name to it's arguments.

        Args:
            integration_json (dict): Dictionary of the examined integration.

        Returns:
            dict. command name to a list of it's arguments.
        """
        command_to_args = {}
        commands = integration_json.get('commands', [])
        for command in commands:
            command_to_args[command['name']] = {}
            for arg in command['arguments']:
                command_to_args[command['name']][arg['name']] = arg.get('required', False)

        return command_to_args

    def is_subset_dictionary(self, new_dict, old_dict):
        """Check if the new dictionary is a sub set of the old dictionary.

        Args:
            new_dict (dict): current branch result from _get_command_to_args
            old_dict (dict): master branch result from _get_command_to_args

        Returns:
            bool. Whether the new dictionary is a sub set of the old dictionary.
        """
        for arg, required in old_dict.items():
            if arg not in new_dict.keys():
                return False

            if required != new_dict[arg] and new_dict[arg]:
                return False

        for arg, required in new_dict.items():
            if arg not in old_dict.keys() and required:
                return False

        return True

    def is_changed_command_name_or_arg(self):
        """Check if a command name or argument as been changed.

        Returns:
            bool. Whether a command name or argument as been changed.
        """
        current_command_to_args = self._get_command_to_args(self.current_integration)
        old_command_to_args = self._get_command_to_args(self.old_integration)

        for command, args_dict in old_command_to_args.items():
            if command not in current_command_to_args.keys() or \
                    not self.is_subset_dictionary(current_command_to_args[command], args_dict):
                print_error("Possible backwards compatibility break, You've changed the name of a command or its arg in"
                            " the file {0} please undo, the command was:\n{1}".format(self.file_path, command))
                self._is_valid = False
                return True

        return False

    def _is_sub_set(self, supposed_bigger_list, supposed_smaller_list):
        """Check if supposed_smaller_list is a subset of the supposed_bigger_list"""
        for check_item in supposed_smaller_list:
            if check_item not in supposed_bigger_list:
                return False

        return True

    def _get_command_to_context_paths(self, integration_json):
        """Get a dictionary command name to it's context paths.

        Args:
            integration_json (dict): Dictionary of the examined integration.

        Returns:
            dict. command name to a list of it's context paths.
        """
        command_to_context_list = {}
        commands = integration_json.get('commands', [])
        for command in commands:
            context_list = []
            for output in command['outputs']:
                context_list.append(output['contextPath'])

            command_to_context_list[command['name']] = sorted(context_list)

        return command_to_context_list

    def is_changed_context_path(self):
        """Check if a context path as been changed.

        Returns:
            bool. Whether a context path as been changed.
        """
        current_command_to_context_paths = self._get_command_to_context_paths(self.current_integration)
        old_command_to_context_paths = self._get_command_to_context_paths(self.old_integration)

        for old_command, old_context_paths in old_command_to_context_paths.items():
            if old_command not in current_command_to_context_paths.keys() or \
                    not self._is_sub_set(current_command_to_context_paths[old_command],
                                         old_context_paths):
                print_error("Possible backwards compatibility break, You've changed the context in the file {0} please "
                            "undo, the command is:\n{1}".format(self.file_path, old_command))
                self._is_valid = False
                return True

        return False

    def _get_field_to_required_dict(self, integration_json):
        """Get a dictionary field name to its required status.

        Args:
            integration_json (dict): Dictionary of the examined integration.

        Returns:
            dict. Field name to its required status.
        """
        field_to_required = {}
        configuration = integration_json.get('configuration')
        for field in configuration:
            field_to_required[field.get('name')] = field.get('required', False)

        return field_to_required

    def is_added_required_fields(self):
        """Check if required field were added."""
        current_field_to_required = self._get_field_to_required_dict(self.current_integration)
        old_field_to_required = self._get_field_to_required_dict(self.old_integration)

        for field, required in current_field_to_required.items():
            if (field not in old_field_to_required.keys() and required) or \
                    (required and field in old_field_to_required.keys() and required != old_field_to_required[field]):
                print_error("You've added required fields in the integration "
                            "file '{}', the field is '{}'".format(self.file_path, field))
                self._is_valid = False
                return True

        return False

    def is_docker_image_changed(self):
        """Check if the Docker image was changed or not."""
        if self.old_integration.get('dockerimage', "") != self.current_integration.get('dockerimage', ""):
            print_error("Possible backwards compatibility break, You've changed the docker for the file {}"
                        " this is not allowed.".format(self.file_path))
            self._is_valid = False
            return True

        return False
