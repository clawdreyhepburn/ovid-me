permit(principal, action == Ovid::Action::"read_file", resource);
permit(principal, action == Ovid::Action::"write_file", resource) when { resource.path like "/test/*" };
permit(principal, action == Ovid::Action::"exec", resource) when { resource.command == "npm" };
forbid(principal, action, resource);
