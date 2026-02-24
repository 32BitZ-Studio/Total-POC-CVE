###
# Dumps GitLab's user base to CSV form.
#
# Requires GraphqlClient: pip install python-graphql-client
###
from python_graphql_client import GraphqlClient
import json
import sys
import argparse

top_parser = argparse.ArgumentParser(description='A tool for dumping a GitLab userbase via GraphQL')
top_parser.add_argument('--rurl', action="store", dest="rurl", required=True, help="The remote URL to send the requests to")
args = top_parser.parse_args()

client = GraphqlClient(endpoint=args.rurl)

# first starts at 1
first = 1

query_header = """query
{
    users"""
query_paging_info = ""
query_payload = """
    {
        pageInfo {
          hasNextPage
          hasPreviousPage
          endCursor
          startCursor
        }
        nodes {
          id
          bot
          username
          email
          publicEmail
          name
          webUrl
          webPath
          avatarUrl
          state
          location
          status {
            emoji
            availability
            message
            messageHtml
          }
          userPermissions {
            createSnippet
          }
          groupCount
          groups {
            nodes{
              id
              name
              fullName
              fullPath
            }
          }
          starredProjects {
            nodes{
              name
              path
              fullPath
            }
          }
          projectMemberships {
            nodes {
              id
              createdAt
            }
          }
          namespace{
            id
            name
            path
            fullName
            fullPath
            lfsEnabled
            visibility
            requestAccessEnabled
            sharedRunnersSetting
          }
          callouts {
            nodes{
              featureName
              dismissedAt
            }
          }
        }
      }
    }
"""

more_data = True

print("id,username,name,publicEmail,bot")
while more_data == True:
    query = query_header + query_paging_info + query_payload
    json_data = client.execute(query=query)

    if "errors" in json_data:
        print("Received error in response. Exiting. ")
        print(json.dumps(json_data))
        sys.exit(0)

    for user in json_data["data"]["users"]["nodes"]:
        print(user["id"] + "," +  user["username"] + "," + user["name"] + "," + user["publicEmail"] + "," + str(user["bot"]))

    if json_data["data"]["users"]["pageInfo"]["hasNextPage"] == True:
        query_paging_info = "(after:\"" + json_data["data"]["users"]["pageInfo"]["startCursor"] + "\")"
    else:
        more_data = False
