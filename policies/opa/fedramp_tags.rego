# FedRAMP High / IL5 Tag Compliance Policies
#
# This policy validates that all resources have required tags as mandated
# by FedRAMP High and DoD IL5 compliance requirements.
#
# Required Tags:
# - Owner: Team or individual responsible for the resource
# - Environment: production, staging, development, disaster-recovery
# - Classification: IL4, IL5, IL6
# - CostCenter: Budget allocation identifier
# - DataSensitivity: Data classification level
# - Compliance: FedRAMP-High, FedRAMP-Moderate, DoD-IL4, DoD-IL5

package fedramp.tags

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Define required tags
required_tags := {
    "Owner",
    "Environment",
    "Classification",
    "CostCenter",
    "DataSensitivity",
    "Compliance"
}

# Valid values for specific tags
valid_environments := {"production", "staging", "development", "disaster-recovery"}
valid_classifications := {"IL4", "IL5", "IL6"}
valid_compliance := {"FedRAMP-High", "FedRAMP-Moderate", "DoD-IL4", "DoD-IL5"}
valid_sensitivity := {"public", "internal", "confidential", "restricted", "cui"}

# Deny resources missing required tags
deny[msg] if {
    # Get all resources with tags attribute
    resource := input.resource_changes[_]
    resource.change.actions[_] != "delete"

    # Check if resource type should have tags
    has_tags_attribute(resource.type)

    # Get planned tags
    tags := get_tags(resource)

    # Find missing required tags
    missing := required_tags - {tag | tags[tag]}
    count(missing) > 0

    msg := sprintf(
        "Resource '%s' (%s) is missing required tags: %v. All resources must have Owner, Environment, Classification, CostCenter, DataSensitivity, and Compliance tags.",
        [resource.address, resource.type, missing]
    )
}

# Deny invalid Environment tag values
deny[msg] if {
    resource := input.resource_changes[_]
    resource.change.actions[_] != "delete"
    has_tags_attribute(resource.type)

    tags := get_tags(resource)
    env := tags.Environment
    env != null
    not env in valid_environments

    msg := sprintf(
        "Resource '%s' has invalid Environment tag '%s'. Must be one of: %v",
        [resource.address, env, valid_environments]
    )
}

# Deny invalid Classification tag values
deny[msg] if {
    resource := input.resource_changes[_]
    resource.change.actions[_] != "delete"
    has_tags_attribute(resource.type)

    tags := get_tags(resource)
    classification := tags.Classification
    classification != null
    not classification in valid_classifications

    msg := sprintf(
        "Resource '%s' has invalid Classification tag '%s'. Must be one of: %v",
        [resource.address, classification, valid_classifications]
    )
}

# Deny invalid Compliance tag values
deny[msg] if {
    resource := input.resource_changes[_]
    resource.change.actions[_] != "delete"
    has_tags_attribute(resource.type)

    tags := get_tags(resource)
    compliance := tags.Compliance
    compliance != null
    not compliance in valid_compliance

    msg := sprintf(
        "Resource '%s' has invalid Compliance tag '%s'. Must be one of: %v",
        [resource.address, compliance, valid_compliance]
    )
}

# Deny IL5 resources without FedRAMP-High or DoD-IL5 compliance tag
deny[msg] if {
    resource := input.resource_changes[_]
    resource.change.actions[_] != "delete"
    has_tags_attribute(resource.type)

    tags := get_tags(resource)
    tags.Classification == "IL5"
    not tags.Compliance in {"FedRAMP-High", "DoD-IL5"}

    msg := sprintf(
        "Resource '%s' is classified IL5 but has Compliance tag '%s'. IL5 resources must have FedRAMP-High or DoD-IL5 compliance.",
        [resource.address, tags.Compliance]
    )
}

# Warn on empty Owner tag
warn[msg] if {
    resource := input.resource_changes[_]
    resource.change.actions[_] != "delete"
    has_tags_attribute(resource.type)

    tags := get_tags(resource)
    owner := tags.Owner
    owner != null
    trim_space(owner) == ""

    msg := sprintf(
        "Resource '%s' has an empty Owner tag. Please specify the responsible team or individual.",
        [resource.address]
    )
}

# Warn on empty CostCenter tag
warn[msg] if {
    resource := input.resource_changes[_]
    resource.change.actions[_] != "delete"
    has_tags_attribute(resource.type)

    tags := get_tags(resource)
    cost_center := tags.CostCenter
    cost_center != null
    trim_space(cost_center) == ""

    msg := sprintf(
        "Resource '%s' has an empty CostCenter tag. Please specify the budget allocation identifier.",
        [resource.address]
    )
}

# Helper: Check if resource type supports tags
has_tags_attribute(resource_type) if {
    # AWS resources
    startswith(resource_type, "aws_")
} else if {
    # Azure resources
    startswith(resource_type, "azurerm_")
} else if {
    # Google Cloud resources
    startswith(resource_type, "google_")
}

# Helper: Get tags from resource (handles AWS tags and Azure tags)
get_tags(resource) := tags if {
    # AWS-style tags
    tags := resource.change.after.tags
} else := tags if {
    # AWS-style tags_all
    tags := resource.change.after.tags_all
} else := {} {
    true
}

# Helper function to trim whitespace
trim_space(s) := trimmed if {
    trimmed := trim(s, " \t\n\r")
}
