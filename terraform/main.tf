terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "=4.35.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "=3.1.0"
    }
    azapi = {
      source  = "azure/azapi"
      version = "=2.3.0"
    }
  }
}

provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }

  subscription_id = var.subscription_id
}

resource "random_string" "unique" {
  length  = 8
  special = false
  upper   = false
}

data "azurerm_client_config" "current" {}

data "azurerm_log_analytics_workspace" "default" {
  name                = "DefaultWorkspace-${data.azurerm_client_config.current.subscription_id}-${local.loc_short}"
  resource_group_name = "DefaultResourceGroup-${local.loc_short}"
}

resource "azurerm_resource_group" "rg" {
  name     = "rg-${local.gh_repo}-${random_string.unique.result}-${local.loc_for_naming}"
  location = var.location
  tags     = local.tags
}

resource "azurerm_virtual_network" "default" {
  name                = "${local.func_name}-vnet-${local.loc_for_naming}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  address_space       = ["10.41.0.0/16"]

  tags = local.tags
}

resource "azurerm_subnet" "fw" {
  name                 = "AzureFirewallSubnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.default.name
  address_prefixes     = ["10.41.0.0/26"]
}

resource "azurerm_subnet" "fwmgmt" {
  name                 = "AzureFirewallManagementSubnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.default.name
  address_prefixes     = ["10.41.0.64/26"]
}

resource "azurerm_subnet" "default" {
  name                 = "default-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.default.name
  address_prefixes     = ["10.41.1.0/24"]

  delegation {
    name = "Microsoft.App.environments"
    service_delegation {
      name = "Microsoft.App/environments"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action"
      ]
    }
  }
}

resource "azurerm_subnet" "apim" {
  name                 = "apim-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.default.name
  address_prefixes     = ["10.41.2.0/24"]

  // delegate to Microsoft.Web/hostingEnvironments.
  delegation {
    name = "Microsoft.Web.hostingEnvironments"
    service_delegation {
      name = "Microsoft.Web/hostingEnvironments"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/action"
      ]
    }
  }
}

resource "azurerm_subnet" "apim2" {
  name                 = "apim2-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.default.name
  address_prefixes     = ["10.41.3.0/24"]

  delegation {
    name = "Microsoft.Web.serverFarms"
    service_delegation {
      name = "Microsoft.Web/serverFarms"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/action"
      ]
    }
  }
}

resource "azurerm_subnet" "pe" {
  name                 = "pe-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.default.name
  address_prefixes     = ["10.41.5.0/24"]
}


# create NSG for the subnet
resource "azurerm_network_security_group" "nsgapim" {
  name                = "nsg-${local.func_name}-apim"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "AllowHTTPs"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["443"]
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowApim"
    priority                   = 1100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["3443"]
    source_address_prefix      = "ApiManagement"
    destination_address_prefix = "*"
  }

  tags = local.tags
}

resource "azurerm_subnet_network_security_group_association" "nsg_association" {
  subnet_id                 = azurerm_subnet.apim.id
  network_security_group_id = azurerm_network_security_group.nsgapim.id
}

resource "azurerm_subnet_network_security_group_association" "nsg_association2" {
  subnet_id                 = azurerm_subnet.apim2.id
  network_security_group_id = azurerm_network_security_group.nsgapim.id
}

resource "azurerm_public_ip" "fw" {
  name                = "pip-fw-${local.func_name}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  allocation_method   = "Static"

  tags = local.tags
}

resource "azurerm_public_ip" "fwmgmt" {
  name                = "pip-fwmgmt-${local.func_name}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  allocation_method   = "Static"

  tags = local.tags
}

resource "azurerm_firewall" "fw" {
  name                = "fw-${local.func_name}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.fw.id
    public_ip_address_id = azurerm_public_ip.fw.id
  }

  management_ip_configuration {
    name                 = "managementConfiguration"
    subnet_id            = azurerm_subnet.fwmgmt.id
    public_ip_address_id = azurerm_public_ip.fwmgmt.id
  }

  sku_name = "AZFW_VNet"
  sku_tier = "Basic"

  firewall_policy_id = azurerm_firewall_policy.this.id

  tags = local.tags
}


# Diagnostic settings for the firewall
resource "azurerm_monitor_diagnostic_setting" "fw_diag" {
  name                       = "fw-diagnostic-${local.func_name}"
  target_resource_id         = azurerm_firewall.fw.id
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.default.id
  enabled_log {
    category = "AZFWApplicationRule"
  }
  enabled_log {
    category = "AZFWApplicationRuleAggregation"
  }
  enabled_log {
    category = "AZFWDnsQuery"
  }
  enabled_log {
    category = "AZFWFatFlow"
  }
  enabled_log {
    category = "AZFWFlowTrace"
  }
  enabled_log {
    category = "AZFWFqdnResolveFailure"
  }
  enabled_log {
    category = "AZFWIdpsSignature"
  }
  enabled_log {
    category = "AZFWNatRule"
  }
  enabled_log {
    category = "AZFWNatRuleAggregation"
  }
  enabled_log {
    category = "AZFWNetworkRule"
  }
  enabled_log {
    category = "AZFWNetworkRuleAggregation"
  }
  enabled_log {
    category = "AZFWThreatIntel"
  }
  enabled_log {
    category = "AzureFirewallApplicationRule"
  }
  enabled_log {
    category = "AzureFirewallDnsProxy"
  }
  enabled_log {
    category = "AzureFirewallNetworkRule"
  }
  enabled_log {
    category = "AzureFirewallApplicationRule"
  }
  enabled_log {
    category = "AzureFirewallNetworkRule"
  }
}


resource "azurerm_firewall_policy" "this" {
  name                = "policy-${local.func_name}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku                 = "Basic"
}

resource "azurerm_firewall_policy_rule_collection_group" "this" {
  name               = "rule-collection-group-${local.func_name}"
  firewall_policy_id = azurerm_firewall_policy.this.id
  priority           = 100

  application_rule_collection {
    name     = "app-rule-collection-apim"
    priority = 500
    action   = "Allow"
    rule {
      name = "apimcontrolplane"

      protocols {
        type = "Https"
        port = 443
      }
      protocols {
        type = "Https"
        port = 3443
      }
      protocols {
        type = "Mssql"
        port = 3306
      }

      source_addresses  = ["*"]
      destination_fqdns = ["*.azure-api.net", "*.database.net", "azureprofiler.trafficmanager.net", "*.management.azure-api.net"]

    }

    rule {
      name = "internaldiag"
      protocols {
        type = "Https"
        port = 443
      }
      source_addresses  = ["*"]
      destination_fqdns = ["azurewatsonanalysis-prod.core.windows.net", "*.data.microsoft.com", "azureprofiler.trafficmanager.net", "shavamanifestazurecdnprod1.azureedge.net", "shavamanifestcdnprod1.azureedge.net"]
    }

    rule {
      name = "pki"
      protocols {
        type = "Https"
        port = 443
      }
      source_addresses  = ["*"]
      destination_fqdns = ["issuer.pki.azure.com"]
    }

    rule {
      name = "update"
      protocols {
        type = "Http"
        port = 80
      }
      protocols {
        type = "Https"
        port = 443
      }
      source_addresses  = ["*"]
      destination_fqdns = ["*.update.microsoft.com", "*.ctldl.windowsupdate.com", "ctldl.windowsupdate.com", "download.windowsupdate.com"]
    }

    rule {
      name = "go"
      protocols {
        type = "Http"
        port = 80
      }
      protocols {
        type = "Https"
        port = 443
      }
      source_addresses  = ["*"]
      destination_fqdns = ["go.microsoft.com"]
    }

    rule {
      name = "oneocsp"
      protocols {
        type = "Http"
        port = 80
      }
      protocols {
        type = "Https"
        port = 443
      }
      source_addresses  = ["*"]
      destination_fqdns = ["oneocsp.microsoft.com", "crl3.digicert.com"]
    }

    rule {
      name = "defender"
      protocols {
        type = "Https"
        port = 443
      }
      source_addresses  = ["*"]
      destination_fqdns = ["wdcp.microsoft.com", "wdcpalt.microsoft.com"]
    }

    rule {
      name = "api"
      protocols {
        type = "Https"
        port = 443
      }
      source_addresses  = ["*"]
      destination_fqdns = ["msedge.api.cdp.microsoft.com"]
    }

    rule {
      name = "partner"
      protocols {
        type = "Https"
        port = 443
      }
      source_addresses  = ["*"]
      destination_fqdns = ["partner.prod.repmap.microsoft.com"]
    }

    rule {
      name = "events"
      protocols {
        type = "Https"
        port = 443
      }
      source_addresses  = ["*"]
      destination_fqdns = ["v10.events.data.microsoft.com"]
    }

    rule {
      name = "managedidentity"
      protocols {
        type = "Https"
        port = 443
      }
      source_addresses  = ["*"]
      destination_fqdns = ["login.microsoftonline.com"]
    }

    rule {
      name = "arm"
      protocols {
        type = "Https"
        port = 443
      }
      source_addresses  = ["*"]
      destination_fqdns = ["management.azure.com"]
    }

    rule {
      name = "ifconfig"
      protocols {
        type = "Https"
        port = 443
      }
      source_addresses  = ["*"]
      destination_fqdns = ["ifconfig.me"]
    }


  }

  network_rule_collection {
    name     = "net-rule-collection-apim"
    priority = 400
    action   = "Allow"

    rule {
      name                  = "123"
      protocols             = ["UDP"]
      source_addresses      = ["*"]
      destination_addresses = ["*"]
      destination_ports     = ["123"]
    }

    rule {
      name                  = "ServiceTags"
      protocols             = ["TCP", "UDP"]
      source_addresses      = ["*"]
      destination_addresses = ["AzureMonitor", "ApiManagement", "Sql", "Storage", "AzureKeyVault", "EventHub"]
      destination_ports     = ["80", "443", "445", "3443", "1433", "12000", "1886"]
    }

    rule {
      name                  = "Redis"
      protocols             = ["TCP"]
      source_addresses      = ["*"]
      destination_addresses = ["*"]
      destination_ports     = ["6380"]
    }
  }
}

resource "azurerm_route_table" "apim_route_table" {
  name                = "rt-${local.func_name}-apim"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  route {
    name                   = "to-firewall"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = azurerm_firewall.fw.ip_configuration[0].private_ip_address
  }

  route {
    name           = "to-apim"
    address_prefix = "ApiManagement"
    next_hop_type  = "Internet"
  }

  tags = local.tags
}


resource "azurerm_subnet_route_table_association" "apim_route_table_association" {
  subnet_id      = azurerm_subnet.apim2.id
  route_table_id = azurerm_route_table.apim_route_table.id
}

resource "azapi_resource" "apim" {
  type      = "Microsoft.ApiManagement/service@2024-06-01-preview"
  name      = "apim-sv2-${local.func_name}-${random_string.unique.result}"
  parent_id = azurerm_resource_group.rg.id
  identity {
    type = "SystemAssigned"
  }
  location = azurerm_resource_group.rg.location
  tags     = local.tags
  body = {
    properties = {
      publisherEmail = "publisher@example.com"
      publisherName  = "Publisher Name"
      virtualNetworkConfiguration = {
        subnetResourceId = azurerm_subnet.apim2.id
      }
      virtualNetworkType = "External"
    }
    sku = {
      capacity = 1
      name     = "StandardV2"
    }
  }
}

# resource "azurerm_private_endpoint" "apim" {
#   name                = "pe-apim-${local.func_name}"
#   location            = azurerm_resource_group.rg.location
#   resource_group_name = azurerm_resource_group.rg.name

#   subnet_id = azurerm_subnet.pe.id

#   private_service_connection {
#     name                           = "psc-apim-${local.func_name}"
#     is_manual_connection           = false
#     private_connection_resource_id = azapi_resource.apim.id
#     subresource_names              = ["gateway"]
#   }
#   private_dns_zone_group {
#     name                 = "apim-dns-zone-group"
#     private_dns_zone_ids = [azurerm_private_dns_zone.apim.id]
#   }

#   tags = local.tags
# }

resource "azurerm_private_dns_zone" "apim" {
  name                = "privatelink.azure-api.net"
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_private_dns_zone_virtual_network_link" "apim" {
  name                  = "apim"
  resource_group_name   = azurerm_resource_group.rg.name
  private_dns_zone_name = azurerm_private_dns_zone.apim.name
  virtual_network_id    = azurerm_virtual_network.default.id
}

resource "azurerm_api_management_api" "api" {
  api_management_name = azapi_resource.apim.name
  resource_group_name = azurerm_resource_group.rg.name
  revision            = 1
  name                = "echoheaders"
  display_name        = "Echo Headers"
  path                = "echoheaders"
  protocols           = ["https"]

  subscription_required = false
}

resource "azurerm_api_management_api_operation" "echo" {
  operation_id        = "echo"
  api_name            = azurerm_api_management_api.api.name
  api_management_name = azapi_resource.apim.name
  resource_group_name = azurerm_resource_group.rg.name

  display_name = "Echo Headers"
  method       = "GET"
  url_template = "/"
}

resource "azurerm_api_management_api_operation_policy" "echopolicy" {
  api_name            = azurerm_api_management_api.api.name
  api_management_name = azapi_resource.apim.name
  resource_group_name = azurerm_resource_group.rg.name
  operation_id        = azurerm_api_management_api_operation.echo.operation_id

  xml_content = <<XML
<policies>
    <inbound>
        <base />
        <return-response>
            <set-status code="200" reason="OK" />
            <set-body>@{
                var headers = context.Request.Headers
                                .Where(h => h.Key != "A" && h.Key != "B" && h.Key != "C")
                                .Select(h => string.Format("{0}: {1}", h.Key, String.Join(", ", h.Value)))
                                .ToArray<string>(); 
                return String.Join(" ||| ", headers);
            }</set-body>
        </return-response>
    </inbound>
    <backend>
        <base />
    </backend>
    <outbound>
        <base />
    </outbound>
</policies>
XML

}

resource "azurerm_api_management_api" "api2" {
  api_management_name = azapi_resource.apim.name
  resource_group_name = azurerm_resource_group.rg.name
  revision            = 1
  name                = "ifconfig"
  display_name        = "Get IP Address"
  path                = "ifconfig"
  protocols           = ["https"]

  service_url = "https://ifconfig.me"

  subscription_required = false
}

resource "azurerm_api_management_api_operation" "getip" {
  operation_id        = "getip"
  api_name            = azurerm_api_management_api.api2.name
  api_management_name = azapi_resource.apim.name
  resource_group_name = azurerm_resource_group.rg.name

  display_name = "Get IP"
  method       = "GET"
  url_template = "/"
}

resource "azurerm_container_app_environment" "this" {
  name                       = "ace-${local.func_name}"
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.default.id

  infrastructure_subnet_id = azurerm_subnet.default.id

  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
  }

  tags = local.tags

  lifecycle {
    ignore_changes = [
      infrastructure_resource_group_name
    ]
  }

}

resource "azurerm_container_app" "frontend" {
  name                         = "bastion-${local.func_name}"
  container_app_environment_id = azurerm_container_app_environment.this.id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"

  template {
    container {
      name   = "frontend"
      image  = "ghcr.io/implodingduck/az-tf-util-image:latest"
      cpu    = 0.25
      memory = "0.5Gi"



    }
    min_replicas = 1
    max_replicas = 1
  }


  identity {
    type = "SystemAssigned"
  }
  tags = local.tags

}