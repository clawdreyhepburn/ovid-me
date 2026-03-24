permit(principal, action == Ovid::Action::"exec", resource) when { resource.command in ["git", "npm", "docker"] };
permit(principal, action == Ovid::Action::"read_file", resource);
forbid(principal, action, resource);
