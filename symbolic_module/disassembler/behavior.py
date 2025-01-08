
# Behavior Modeling Class
class Behavior:
    def __init__(self, name, elements=None):
        self.name = name
        self.elements = elements or []

    def add_action(self, action):
        self.elements.append(action)

    def __repr__(self):
        return f"{self.name}: {self.elements}"


# Operations for modeling
class BehaviorOperations:
    @staticmethod
    def prefixing(action, behavior):
        """Defines a.B operation"""
        return Behavior(name=f"{action}.{behavior.name}", elements=[action] + behavior.elements)

    @staticmethod
    def nondeterministic_choice(behavior1, behavior2):
        """Defines A + B operation"""
        return Behavior(name=f"({behavior1.name} + {behavior2.name})", elements=behavior1.elements + behavior2.elements)

    @staticmethod
    def validate_trace_against_behavior(trace, behavior):
        """
        Validate if a trace conforms to a behavior structure.
        """
        flat_behavior = behavior.elements
        flat_trace = [insn for step in trace for insn in step]  # Flatten the trace
        return all(action in flat_trace for action in flat_behavior)
