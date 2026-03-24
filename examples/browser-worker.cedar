permit(principal, action in [Ovid::Action::"use_tool", Ovid::Action::"web_fetch"], resource);
forbid(principal, action == Ovid::Action::"exec", resource);
forbid(principal, action == Ovid::Action::"write_file", resource);
