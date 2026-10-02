'use strict';
/* =====================================================================
   REFERENCE TABLES: IQ and grounded agents.
   ===================================================================== */
const REF_IQ = [
  {
    id: 'iq', title: 'IQ products: whose identity reaches the data',
    intro: 'Each IQ workload stands alone, and you can combine them in one agent. Preview features are marked. Check them before a customer demo.',
    cols: ['Product and source', 'Identity at the data', 'Who trims the results', 'Labels and DLP', 'Watch out for', 'Tab'],
    rows: [
      ['Microsoft 365 Copilot and Work IQ (MCP, A2A, REST)', `Delegated user token, scope <code>${ID.workiq.uri}/WorkIQAgent.Ask</code>. Admin consent required, and there is no application permission`, 'Microsoft 365 permissions on every request, plus a Rego tenant policy on path and operation', 'Sensitivity labels apply. Encrypted items need VIEW and EXTRACT. DLP can exclude labelled files from Copilot', 'Overshared sites become Copilot answers. Writes are off by default, keep it that way until you need them', 'workiq-mcp'],
      ['Foundry IQ, indexed sources: Blob, ADLS Gen2, indexed SharePoint, OneLake (preview)', 'Caller in Authorization (RBAC role), user in <code>x-ms-query-source-authorization</code>, audience https://search.azure.com', 'Azure AI Search, from ACLs, RBAC scopes or labels ingested at indexing time. Groups are expanded through Graph per query', 'Purview labels where the source ingests them', 'No <code>ingestionPermissionOptions</code> means unfiltered results. ACL changes wait for the next indexer run', 'foundry-iq'],
      ['Foundry IQ, remote SharePoint (preview)', 'User token in <code>x-ms-query-source-authorization</code>', 'SharePoint itself, through the Copilot Retrieval API. Nothing is indexed', 'ACLs and Purview labels out of the box', 'Each user needs a Microsoft 365 Copilot license', 'foundry-iq'],
      ['Foundry IQ, Work IQ knowledge source (preview)', 'User assertion for your connector app in <code>x-ms-query-work-iq-source-authorization</code>. Search runs OBO with a federated credential on its managed identity', 'Work IQ, with Microsoft 365 permissions', 'As for Work IQ', 'May use capabilities that act, not only read. Data may leave the Azure compliance boundary', 'foundry-workiq'],
      ['Fabric IQ: ontology and Power BI semantic model (preview)', 'OBO, the signed-in user', 'Fabric permissions and governance for that user', 'Fabric and Purview policies', 'Make sure the OBO path is used end to end', 'iq-oversharing'],
      ['Fabric IQ: data agent MCP endpoint (preview)', 'A user <b>or</b> a service principal token for https://api.fabric.microsoft.com', 'Fabric, for whichever identity called', 'Fabric and Purview policies', 'With a service principal, every user gets the principal\'s view', 'iq-oversharing'],
    ],
  },
  {
    id: 'oversharing', title: 'Oversharing controls',
    intro: 'Identity keeps the agent honest about <i>who</i> is asking. These controls fix <i>what</i> that person can reach, which is where most oversharing really lives.',
    cols: ['Control', 'Where', 'What it does', 'Tab'],
    rows: [
      ['Data access governance reports', 'SharePoint admin center', 'Finds sites shared with everyone, sites with many unique permissions, and sensitive content shared widely', ''],
      ['Restricted Content Discovery', 'SharePoint site setting', 'Hides a site from organization-wide search and Copilot while you review it. Permissions don\'t change, and people with access can still open files', ''],
      ['Sensitivity labels with encryption', 'Microsoft Purview', 'Copilot and agents return an encrypted item only if the user has VIEW and EXTRACT', 'workiq-mcp'],
      ['DLP for Microsoft 365 Copilot', 'Microsoft Purview', 'Stops Copilot processing files with chosen labels', ''],
      ['Work IQ MCP tenant policy', 'Microsoft 365 admin center, Agents > Tools', 'Read-only by default. Blocks paths, limits collection reads, and treats denials as final', 'workiq-mcp'],
      ['Allow or block MCP servers', 'Microsoft 365 admin center, Agent 365', 'A blocked server is blocked for every user and every agent', ''],
      ['Permission ingestion on knowledge sources', 'Azure AI Search', 'Puts userIds, groupIds and rbacScope on every document so queries can be trimmed', 'iq-oversharing'],
      ['User token on every retrieve', 'Your agent or app', 'Lets Search or the source apply the user\'s rights. Elevated reads that skip trimming need a separate role and header', 'foundry-iq'],
      ['Delegated or OBO access only', 'Entra app registrations', 'Keeps app-only Sites.Read.All and Files.Read.All away from grounding', 'iq-oversharing'],
      ['Conditional Access on the user token', 'Entra ID', 'The token the agent forwards is still subject to MFA, device and risk policy', 'step-up'],
    ],
  },
];
{
  const mcpIdx = REFERENCE.findIndex((s) => s.id === 'mcp');
  REFERENCE.splice(mcpIdx + 1, 0, ...REF_IQ);
  REFERENCE.find((s) => s.id === 'anti')?.rows.push(
    ['Grounding an agent with app-only rights such as Sites.Read.All', 'Every user gets whatever the agent can read, and the logs name the agent, not the person', 'Delegated or OBO access and permission-aware knowledge sources. See the <a href="#flow/iq-oversharing">oversharing tab</a>'],
    ['A knowledge source created without permission ingestion', 'The index has no ACL fields, so results come back unfiltered even with a user token', 'Recreate it with <code>ingestionPermissionOptions</code> and test with two users'],
    ['Expecting Copilot or an agent to fix permissions', 'They apply the permissions you have. Overshared sites become answers', 'Clean up with data access governance reports, Restricted Content Discovery and labels first'],
  );
}
