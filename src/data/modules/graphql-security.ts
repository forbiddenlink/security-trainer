import type { Module } from "../../types";

export const graphqlSecurity: Module = {
  id: "graphql-security",
  title: "GraphQL Security",
  description:
    "Learn to identify and prevent vulnerabilities unique to GraphQL APIs including introspection abuse, query complexity attacks, and authorization bypass.",
  difficulty: "Intermediate",
  xpReward: 150,
  locked: false,
  lessons: [
    {
      id: "graphql-security-intro",
      title: "GraphQL Security Fundamentals",
      type: "theory",
      content: `# GraphQL Security Fundamentals

GraphQL is a powerful query language for APIs, but its flexibility introduces unique security challenges that don't exist in traditional REST APIs.

## How GraphQL Differs from REST

| REST | GraphQL |
|------|---------|
| Multiple endpoints | Single endpoint (\`/graphql\`) |
| Server controls response shape | Client controls query shape |
| Fixed data per endpoint | Client requests specific fields |
| Separate requests per resource | Nested queries in one request |

## The GraphQL Attack Surface

### 1. Self-Documenting Schema
GraphQL has built-in **introspection** - clients can query the schema itself:

\`\`\`graphql
{
  __schema {
    types { name }
  }
}
\`\`\`

Attackers can map your entire API without documentation.

### 2. Client-Controlled Queries
Clients decide what data to fetch, including depth:

\`\`\`graphql
{
  user {
    friends {
      friends {
        friends {
          # Can go arbitrarily deep
        }
      }
    }
  }
}
\`\`\`

This enables denial-of-service attacks.

### 3. Batching
Multiple operations in a single request:

\`\`\`graphql
query {
  user1: user(id: 1) { password }
  user2: user(id: 2) { password }
  user3: user(id: 3) { password }
  # ... thousands more
}
\`\`\`

Bypasses rate limiting that counts requests, not operations.

## Why REST Patterns Don't Fully Apply

- **Endpoint-based security** doesn't work with a single endpoint
- **Rate limiting by request** misses batched operations
- **URL-based logging** doesn't capture query details
- **Caching** is more complex with dynamic queries

GraphQL requires field-level thinking, not endpoint-level.`,
    },
    {
      id: "graphql-introspection",
      title: "Introspection Attacks",
      type: "theory",
      content: `# Introspection Attacks

Introspection is a powerful GraphQL feature that lets clients discover the schema. In production, it's also a powerful reconnaissance tool for attackers.

## What Is Introspection?

GraphQL schemas are self-documenting. Any client can query:

\`\`\`graphql
{
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}
\`\`\`

This returns every type, field, argument, and relationship in your API.

## The Attack Scenario

1. Attacker sends introspection query to \`/graphql\`
2. Receives complete schema including:
   - All query and mutation names
   - All types and their fields
   - Argument names and types
   - Hidden/internal fields you forgot to secure

3. Attacker now knows:
   - \`adminUsers\` query exists (you didn't document it)
   - \`User\` type has \`passwordResetToken\` field
   - \`deleteAllData\` mutation is available

## Real Introspection Query

Tools like GraphQL Voyager or InQL use queries like this:

\`\`\`graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      ...FullType
    }
  }
}

fragment FullType on __Type {
  name
  fields {
    name
    args { name type { name } }
    type { name kind ofType { name } }
  }
}
\`\`\`

## Defense: Disable in Production

**Apollo Server:**
\`\`\`javascript
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
});
\`\`\`

**GraphQL Yoga:**
\`\`\`javascript
const yoga = createYoga({
  schema,
  graphiql: process.env.NODE_ENV !== 'production',
  // Disabling GraphiQL also disables introspection by default
});
\`\`\`

## Keep Introspection for Development

- **Development:** Enable for tooling (GraphiQL, Apollo Studio)
- **Staging:** Consider enabling for QA
- **Production:** Always disable

Attackers will find your schema through introspection before they try anything else.`,
    },
    {
      id: "graphql-depth-complexity",
      title: "Query Depth & Complexity Attacks",
      type: "theory",
      content: `# Query Depth & Complexity Attacks

GraphQL's flexibility allows clients to construct expensive queries that can overwhelm your server. Without limits, a single request can cause denial of service.

## The Depth Attack

Deeply nested queries multiply database calls:

\`\`\`graphql
query ExpensiveQuery {
  users {           # 100 users
    posts {         # 50 posts each = 5,000
      comments {    # 20 comments each = 100,000
        author {    # 1 author each = 100,000
          posts {   # 50 posts each = 5,000,000
            comments {  # ... exponential growth
            }
          }
        }
      }
    }
  }
}
\`\`\`

Each level multiplies the previous. This single query could trigger millions of database operations.

## The Complexity Attack

Even shallow queries can be expensive:

\`\`\`graphql
query WideQuery {
  user1: user(id: 1) { expensiveField }
  user2: user(id: 2) { expensiveField }
  user3: user(id: 3) { expensiveField }
  # ... repeat 1000 times using aliases
}
\`\`\`

## Defense 1: Depth Limiting

Reject queries exceeding a maximum depth:

\`\`\`javascript
import depthLimit from 'graphql-depth-limit';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [depthLimit(5)],  // Max 5 levels deep
});
\`\`\`

Now the attack query fails:
\`\`\`
Query exceeds maximum depth of 5
\`\`\`

## Defense 2: Complexity Analysis

Assign costs to fields and reject expensive queries:

\`\`\`javascript
import { createComplexityRule } from 'graphql-query-complexity';

const complexityRule = createComplexityRule({
  maximumComplexity: 1000,
  estimators: [
    fieldConfigEstimator(),
    simpleEstimator({ defaultComplexity: 1 }),
  ],
});
\`\`\`

In your schema, mark expensive fields:

\`\`\`javascript
posts: {
  type: [Post],
  complexity: ({ childComplexity, args }) =>
    childComplexity * (args.limit || 100)  // Multiplies by result count
}
\`\`\`

## Which to Use?

| Approach | Pros | Cons |
|----------|------|------|
| Depth limiting | Simple, catches nested attacks | Doesn't catch wide queries |
| Complexity analysis | Precise control | More setup required |
| Both | Best protection | Most configuration |

Start with depth limiting. Add complexity analysis if you have expensive fields.`,
    },
    {
      id: "graphql-quiz-1",
      title: "Identify the Vulnerability",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "An attacker sends `{ __schema { types { name fields { name } } } }` to your production GraphQL endpoint and receives your complete API structure. What vulnerability allowed this?",
        options: [
          "SQL Injection in the GraphQL resolver",
          "Introspection is enabled in production",
          "Missing CORS headers on the /graphql endpoint",
          "Broken authentication on the GraphQL server",
        ],
        correctAnswer: 1,
        explanation:
          "The __schema query is GraphQL's introspection feature. It allows clients to query the schema itself. When enabled in production, attackers can discover all types, fields, queries, and mutations in your API - perfect for reconnaissance. Always disable introspection in production environments.",
      },
    },
    {
      id: "graphql-quiz-2",
      title: "Query Depth Attack",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "A GraphQL query requests `user.posts.comments.author.posts.comments.author...` 20 levels deep, causing your server to timeout. What defense is needed?",
        options: [
          "Add rate limiting to the /graphql endpoint",
          "Require authentication for all queries",
          "Implement query depth limiting",
          "Enable response caching",
        ],
        correctAnswer: 2,
        explanation:
          "Query depth limiting rejects queries that exceed a maximum nesting level (e.g., 5-10 levels). This prevents attackers from crafting deeply nested queries that cause exponential database operations. Rate limiting wouldn't help here since it's a single request causing the problem.",
      },
    },
    {
      id: "graphql-authorization",
      title: "Authorization Bypass",
      type: "theory",
      content: `# Authorization Bypass in GraphQL

The most critical GraphQL vulnerability is broken authorization in resolvers. Unlike REST where endpoints are distinct, GraphQL's single endpoint requires careful field-level authorization.

## The Problem: Resolver Trust

Resolvers often return data without checking permissions:

\`\`\`javascript
const resolvers = {
  Query: {
    user: (_, { id }) => db.users.findById(id),  // Anyone can query any user!
  },
  User: {
    email: (parent) => parent.email,  // Returns email to anyone who asks
    ssn: (parent) => parent.ssn,      // Even sensitive fields!
  },
};
\`\`\`

## Attack: IDOR via GraphQL

Just like REST APIs, GraphQL is vulnerable to IDOR:

\`\`\`graphql
# Attacker changes the ID
query {
  user(id: 999) {
    email
    ssn
    bankAccounts {
      accountNumber
      balance
    }
  }
}
\`\`\`

If resolvers don't check ownership, any authenticated user can access any other user's data.

## Defense: Check Authorization in Resolvers

**Option 1: Check in each resolver**

\`\`\`javascript
const resolvers = {
  Query: {
    user: (_, { id }, context) => {
      // Only allow users to query themselves (or admins)
      if (context.user.id !== id && !context.user.isAdmin) {
        throw new ForbiddenError('Not authorized');
      }
      return db.users.findById(id);
    },
  },
  User: {
    ssn: (parent, _, context) => {
      // Extra check for sensitive fields
      if (context.user.id !== parent.id) {
        return null;  // Or throw error
      }
      return parent.ssn;
    },
  },
};
\`\`\`

**Option 2: Use a permission layer**

\`\`\`javascript
import { shield, rule } from 'graphql-shield';

const isOwner = rule()(async (parent, args, ctx) => {
  return ctx.user.id === (args.id || parent.id);
});

const permissions = shield({
  Query: {
    user: isOwner,
  },
  User: {
    ssn: isOwner,
    email: isOwner,
  },
});
\`\`\`

## Common Authorization Mistakes

1. **Only checking at Query level** - Nested fields inherit access
2. **Trusting parent data** - Attacker might reach User through another path
3. **Forgetting mutations** - \`updateUser\` needs same checks as \`user\` query
4. **Batch queries** - Each aliased query needs individual auth checks

## The Rule

**Every resolver that returns sensitive data must verify the requesting user has permission to access that specific record.**`,
    },
    {
      id: "graphql-security-lab",
      title: "Lab: Secure a GraphQL Resolver",
      type: "lab",
      content:
        "This GraphQL resolver returns user data without authorization checks. Your mission: Add field-level authorization so users can only access their own sensitive data. Check context.user.id against the requested user's ID and throw an error or return null for unauthorized access.",
      lab: {
        initialCode: `const resolvers = {
  Query: {
    user: async (_, { id }, context) => {
      // VULNERABLE: No authorization check!
      const user = await db.users.findById(id);
      return user;
    },
  },
  User: {
    email: (parent, _, context) => {
      // VULNERABLE: Returns email to anyone
      return parent.email;
    },
    ssn: (parent, _, context) => {
      // VULNERABLE: Returns SSN to anyone!
      return parent.ssn;
    },
  },
};`,
        solutionCode: `const resolvers = {
  Query: {
    user: async (_, { id }, context) => {
      // Check if user is authenticated
      if (!context.user) {
        throw new AuthenticationError('Must be logged in');
      }
      const user = await db.users.findById(id);
      return user;
    },
  },
  User: {
    email: (parent, _, context) => {
      // Only return email to the owner or admin
      if (context.user.id !== parent.id && !context.user.isAdmin) {
        return null;
      }
      return parent.email;
    },
    ssn: (parent, _, context) => {
      // Only return SSN to the owner (never to admins)
      if (context.user.id !== parent.id) {
        throw new ForbiddenError('Not authorized');
      }
      return parent.ssn;
    },
  },
};`,
        instructions:
          "Add authorization checks using context.user.id. Compare it to parent.id or args.id. Return null or throw an error for unauthorized access.",
      },
    },
  ],
};
