import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_asset_surface_analyze_saves_registry_and_runs_retrohunt(client: AsyncClient):
    response = await client.post(
        "/api/asset-surface/analyze",
        data={
            "provider": "local",
            "use_ai": "false",
            "inventory_name": "unit asset inventory",
            "text": (
                "asset_id,name,asset_type,environment,owner,ip_addresses,domains,ports,technologies,products,suppliers,dependencies,exposure,criticality,tags\n"
                "asset-0001,customer-portal,web-app,prod,Digital,203.0.113.10,portal.example.com,\"80;443\",nginx,portal,internal,npm,internet,critical,customer-data\n"
            ),
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["case_id"]
    assert payload["registry_summary"]["created"] == 1
    assert payload["retrohunt_summary"]["assets_checked"] == 1
    assert payload["assets"][0]["technologies"] == ["nginx"]
    assert payload["assets"][0]["products"] == ["portal"]


@pytest.mark.asyncio
async def test_asset_surface_upload_can_sync_assets_to_company_space(client: AsyncClient):
    space_response = await client.post(
        "/api/threat-radar/spaces",
        json={
            "name": "Example Product Security Space",
            "owner": "PSIRT",
            "sector": "Technology",
            "region": "Global",
            "tags": ["product-security"],
        },
    )
    assert space_response.status_code == 201
    space_id = space_response.json()["id"]

    response = await client.post(
        "/api/asset-surface/analyze",
        data={
            "provider": "local",
            "use_ai": "false",
            "inventory_name": "space scoped inventory",
            "company_space_id": space_id,
            "text": (
                "asset_id,name,asset_type,environment,owner,ip_addresses,domains,ports,technologies,product_name,component_name,exposure,criticality,tags\n"
                "asset-ps-001,bluefield-fw,dpu_firmware,prod,Firmware Team,10.70.0.10,,443,bluefield,BlueField DPU,bluefield-firmware,internal,critical,firmware\n"
            ),
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["company_space_id"] == space_id
    assert payload["company_space_assets_synced"] == 1

    detail = await client.get(f"/api/threat-radar/spaces/{space_id}")
    assert detail.status_code == 200
    space_assets = detail.json()["assets"]
    assert len(space_assets) == 1
    assert space_assets[0]["asset_id"] == "asset-ps-001"
    assert space_assets[0]["products"] == ["bluefield-dpu"]
    assert "bluefield-firmware" in space_assets[0]["components"]


@pytest.mark.asyncio
async def test_asset_surface_analyze_accepts_multiple_inventory_files(client: AsyncClient):
    csv_a = (
        "asset_id,name,asset_type,environment,owner,ip_addresses,domains,ports,technologies,exposure,criticality,tags\n"
        "asset-multi-001,public-api,api_service,prod,API Team,203.0.113.20,api.example.com,443,fastapi,internet,critical,api\n"
    )
    csv_b = (
        "asset_id,name,asset_type,environment,owner,ip_addresses,domains,ports,technologies,exposure,criticality,tags\n"
        "asset-multi-002,build-runner,ci_runner,prod,Build Team,10.40.10.50,,22,docker,internal,high,ci\n"
    )

    response = await client.post(
        "/api/asset-surface/analyze",
        data={"provider": "local", "use_ai": "false", "inventory_name": "multi-file inventory"},
        files=[
            ("files", ("assets-a.csv", csv_a.encode("utf-8"), "text/csv")),
            ("files", ("assets-b.csv", csv_b.encode("utf-8"), "text/csv")),
        ],
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["asset_count"] == 2
    assert payload["filename"] == "assets-a.csv; assets-b.csv"
    assert {asset["asset_id"] for asset in payload["assets"]} == {"asset-multi-001", "asset-multi-002"}


@pytest.mark.asyncio
async def test_asset_surface_accepts_product_security_inventory_bundle(client: AsyncClient):
    asset_inventory = (
        "asset_id,name,asset_type,environment,owner,ip_addresses,domains,ports,technologies,exposure,criticality,tags\n"
        "asset-ps-001,product-download-portal,web-app,prod,PSIRT,203.0.113.50,download.example.com,443,nginx,internet,critical,customer-facing\n"
    )
    product_inventory = (
        "product_id,product_family,product_name,product_line,business_unit,security_owner,engineering_owner,psirt_owner,supported_status,release_channel,customer_deployment_model,criticality,tags\n"
        "prod-bluefield,BlueField,BlueField DPU,Networking,Data Center,Product Security,DPU Engineering,PSIRT,supported,stable,on-prem,critical,dpu\n"
    )
    component_inventory = (
        "component_id,product_id,component_name,component_type,component_version,firmware_version,driver_branch,sdk_version,container_image,repository,build_system,trust_boundary,privilege_level,attack_surface,owner,tags\n"
        "comp-bluefield-fw,prod-bluefield,BlueField firmware,firmware,4.9.1,4.9.1,,,registry.example/bluefield-fw,git.example/fw,jenkins,host_to_firmware,ring0,management_interface,DPU Engineering,firmware\n"
    )
    dependency_inventory = (
        "dependency_id,component_id,package_name,package_version,package_type,purl,cpe,supplier,license,source_repository,sbom_id,used_in_build,used_at_runtime,internet_reachable,customer_shipped,criticality,tags\n"
        "dep-openssl,comp-bluefield-fw,openssl,3.0.13,deb,pkg:deb/debian/openssl@3.0.13,cpe:2.3:a:openssl:openssl:3.0.13,OpenSSL,Apache-2.0,https://github.com/openssl/openssl,sbom-bluefield,true,true,false,true,high,crypto\n"
    )
    exposure_inventory = (
        "exposure_id,product_id,component_id,deployment_model,environment,exposure_type,reachable_from,required_privilege,trust_boundary,customer_exposure,internet_facing,multi_tenant,cloud_relevant,firmware_persistence_possible,secure_boot_relevant,telemetry_sources,detection_available,mitigation_available,patch_status\n"
        "exp-bluefield-mgmt,prod-bluefield,comp-bluefield-fw,on-prem,prod,management_interface,admin-network,admin,network_to_management_plane,customer-managed,false,false,false,true,true,syslog;edr,true,true,patched\n"
    )

    response = await client.post(
        "/api/asset-surface/analyze",
        data={"provider": "local", "use_ai": "false", "inventory_name": "product security bundle"},
        files=[
            ("files", ("asset_inventory.csv", asset_inventory.encode("utf-8"), "text/csv")),
            ("files", ("product_inventory.csv", product_inventory.encode("utf-8"), "text/csv")),
            ("files", ("component_inventory.csv", component_inventory.encode("utf-8"), "text/csv")),
            ("files", ("dependency_sbom_inventory.csv", dependency_inventory.encode("utf-8"), "text/csv")),
            ("files", ("product_exposure_inventory.csv", exposure_inventory.encode("utf-8"), "text/csv")),
        ],
    )

    assert response.status_code == 200
    payload = response.json()
    asset_ids = {asset["asset_id"] for asset in payload["assets"]}
    assert payload["asset_count"] == 5
    assert {
        "asset-ps-001",
        "prod-bluefield",
        "comp-bluefield-fw",
        "dep-openssl",
        "exp-bluefield-mgmt",
    } <= asset_ids
    dependency = next(asset for asset in payload["assets"] if asset["asset_id"] == "dep-openssl")
    assert dependency["asset_type"] == "deb"
    assert "openssl" in dependency["dependencies"]


@pytest.mark.asyncio
async def test_asset_surface_csv_schema_endpoint_returns_strict_header(client: AsyncClient):
    response = await client.get("/api/asset-surface/csv-schema")

    assert response.status_code == 200
    payload = response.json()
    assert payload["template_header"].startswith("asset_id,name,asset_type")
    assert "products" not in payload["columns"]
    assert "suppliers" not in payload["columns"]
    assert "dependencies" not in payload["columns"]
    assert "technologies" in payload["columns"]


@pytest.mark.asyncio
async def test_asset_surface_retrohunt_endpoint_accepts_saved_assets(client: AsyncClient):
    create_response = await client.post(
        "/api/asset-surface/analyze",
        data={
            "provider": "local",
            "use_ai": "false",
            "inventory_name": "unit asset inventory",
            "text": "vpn.example.com 198.51.100.20 ports 443 public vpn",
        },
    )
    assert create_response.status_code == 200

    response = await client.post("/api/asset-surface/retrohunt", json={"asset_ids": []})

    assert response.status_code == 200
    assert response.json()["assets_checked"] >= 1
