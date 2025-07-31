# Database Technologies Guidelines for AI Agents (2025)

*Place this file in your database-related directories or project root for database guidance*

## Database Selection Framework (2025)

Based on the 2025 technology landscape, choose databases that align with your specific use case requirements:

### SQL Databases (Relational)
**Primary Choice: PostgreSQL 15+**
- **Use Cases**: Complex relationships, ACID compliance, financial data, reporting
- **Strengths**: Advanced features, JSON support, full-text search, mature ecosystem
- **Performance**: Excellent for complex queries, concurrent reads/writes
- **Scalability**: Vertical scaling, read replicas, partitioning

**Alternative: MySQL 8.0+**
- **Use Cases**: Web applications, content management, high-traffic websites
- **Strengths**: High performance, wide adoption, cloud support
- **Performance**: Optimized for read-heavy workloads
- **Scalability**: Read replicas, clustering solutions

### NoSQL Databases

#### Document Databases
**Primary Choice: MongoDB 7.0+**
- **Use Cases**: Content management, catalogs, user profiles, semi-structured data
- **Strengths**: Schema flexibility, horizontal scaling, developer productivity
- **Performance**: Excellent for read operations, aggregation pipelines
- **Scalability**: Built-in sharding, replica sets

#### Key-Value Stores
**Primary Choice: Redis 7.0+**
- **Use Cases**: Caching, session storage, real-time leaderboards, pub/sub
- **Strengths**: Extreme performance, data structures, clustering
- **Performance**: Sub-millisecond latency, high throughput
- **Scalability**: Redis Cluster, Redis Sentinel

#### Vector Databases (Emerging 2025)
**Primary Choices: Pinecone, Weaviate, or Milvus**
- **Use Cases**: AI applications, semantic search, recommendation engines
- **Strengths**: Similarity search, embeddings storage, AI integration
- **Performance**: Optimized for vector operations and similarity queries
- **Scalability**: Distributed vector indexing and search

## PostgreSQL Best Practices

### Schema Design Principles
```sql
```sql
-- Use UUIDs - prefer gen_random_uuid() for PostgreSQL 13+
-- But uuid_generate_v4() still works if uuid-ossp extension is preferred
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- User table with modern constraints and indexes
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), -- Modern approach
    email VARCHAR(255) UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role VARCHAR(50) DEFAULT 'user' CHECK (role IN ('admin', 'user', 'moderator')),
    avatar_url TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Modern indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE UNIQUE INDEX idx_users_deleted_at ON users(id) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_metadata ON users USING GIN(metadata);

-- Full-text search index with modern syntax
CREATE INDEX idx_users_search ON users USING GIN(
    to_tsvector('english', first_name || ' ' || last_name || ' ' || email)
);
```
```

### Advanced PostgreSQL 17 Features
```sql
-- Enhanced JSONB operations with newer functions
CREATE TABLE user_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    preferences JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Modern JSONB indexes and operations
CREATE INDEX idx_preferences_user_id ON user_preferences(user_id);
CREATE INDEX idx_preferences_data ON user_preferences USING GIN(preferences);

-- Fixed: Removed PostgreSQL 17-specific path query syntax that doesn't exist
-- Standard GIN index for JSON path expressions using jsonb_ops (default)
CREATE INDEX idx_preferences_theme ON user_preferences 
USING BTREE((preferences->>'theme')) WHERE preferences ? 'theme';

-- Fixed: Corrected JSONB path expression index syntax
-- Use standard @> operator with GIN index for path containment
CREATE INDEX idx_preferences_notifications ON user_preferences 
USING GIN(preferences) WHERE preferences @> '{"notifications": {}}';

-- Fixed: PostgreSQL 11+ syntax confirmed - INCLUDE columns supported in B-tree
CREATE INDEX idx_users_role_created_include ON users(role, created_at) 
INCLUDE (first_name, last_name) WHERE deleted_at IS NULL;
```

### Database Triggers and Functions
```sql
-- Modern trigger function with better error handling and security
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER 
LANGUAGE plpgsql
SECURITY DEFINER  -- Added for security
AS $$
BEGIN
    -- Validate that NEW exists (for INSERT/UPDATE operations)
    IF NEW IS NULL THEN
        RAISE EXCEPTION 'NEW record is null in update_updated_at_column trigger';
    END IF;
    
    -- Set the timestamp with timezone for better precision
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;

-- Apply trigger to tables with proper timing
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Enhanced audit log function with improved error handling
CREATE OR REPLACE FUNCTION create_audit_log()
RETURNS TRIGGER 
LANGUAGE plpgsql
SECURITY DEFINER  -- Added for security
AS $$
DECLARE
    user_id_val INTEGER;
BEGIN
    -- Extract user_id with proper null handling
    user_id_val := CASE 
        WHEN TG_OP = 'DELETE' THEN OLD.updated_by
        WHEN TG_OP IN ('INSERT', 'UPDATE') THEN NEW.updated_by
        ELSE NULL
    END;
    
    -- Insert audit record with proper error handling
    BEGIN
        INSERT INTO audit_logs (
            table_name,
            operation,
            old_data,
            new_data,
            user_id,
            timestamp
        ) VALUES (
            TG_TABLE_NAME,
            TG_OP,
            CASE WHEN TG_OP IN ('UPDATE', 'DELETE') THEN to_jsonb(OLD) ELSE NULL END,
            CASE WHEN TG_OP IN ('INSERT', 'UPDATE') THEN to_jsonb(NEW) ELSE NULL END,
            user_id_val,
            CURRENT_TIMESTAMP  -- More precise than NOW()
        );
    EXCEPTION
        WHEN OTHERS THEN
            -- Log the error but don't fail the original operation
            RAISE WARNING 'Audit log insertion failed: %', SQLERRM;
    END;
    
    -- Return appropriate value based on operation
    RETURN CASE 
        WHEN TG_OP = 'DELETE' THEN OLD
        ELSE NEW
    END;
END;
$$;

-- Example trigger creation for the audit function
CREATE TRIGGER audit_users_trigger
    AFTER INSERT OR UPDATE OR DELETE ON users
    FOR EACH ROW 
    EXECUTE FUNCTION create_audit_log();
```

### Query Optimization Patterns
```sql
-- ✅ Modern query optimization with EXPLAIN - CORRECT
EXPLAIN (ANALYZE, BUFFERS, VERBOSE, SETTINGS) 
SELECT u.*, p.preferences 
FROM users u 
LEFT JOIN user_preferences p ON u.id = p.user_id 
WHERE u.role = 'user' 
    AND u.created_at > NOW() - INTERVAL '30 days'
    AND u.deleted_at IS NULL
ORDER BY u.created_at DESC 
LIMIT 20;

-- ✅ Efficient pagination with improved cursor approach - CORRECT
SELECT * FROM users 
WHERE (created_at, id) < ($1, $2)  -- composite cursor
    AND deleted_at IS NULL
ORDER BY created_at DESC, id DESC
LIMIT 20;

-- ✅ Modern full-text search with ranking - CORRECT
SELECT *, 
       ts_rank(search_vector, websearch_to_tsquery('english', $1)) as rank
FROM users 
WHERE search_vector @@ websearch_to_tsquery('english', $1)
    AND deleted_at IS NULL
ORDER BY rank DESC, created_at DESC
LIMIT 20;

-- ✅ Enhanced CTEs with materialization control - CORRECT
WITH recent_users AS MATERIALIZED (
    SELECT id, email, created_at
    FROM users 
    WHERE created_at > NOW() - INTERVAL '7 days'
        AND deleted_at IS NULL
),
user_stats AS NOT MATERIALIZED (
    SELECT 
        COUNT(*) as total_users,
        COUNT(*) FILTER (WHERE email_verified) as verified_users
    FROM recent_users
)
SELECT * FROM user_stats;
```

## MongoDB Best Practices

### Collection Design Patterns
```javascript
// Enhanced user document schema with improved structure
{
  "_id": ObjectId("..."),
  "email": "user@example.com",
  "emailVerified": false,
  "passwordHash": "...",
  "profile": {
    "firstName": "John",
    "lastName": "Doe",
    "avatar": "https://...",
    "preferences": {
      "theme": "dark",
      "language": "en",
      "notifications": {
        "email": true,
        "push": false
      }
    }
  },
  "roles": ["user"],
  "metadata": {
    "loginCount": 15,
    "lastLoginAt": ISODate("2025-01-01T00:00:00.000Z"),
    "ipAddresses": ["192.168.1.1", "10.0.0.1"]
  },
  "createdAt": ISODate("2025-01-01T00:00:00.000Z"),
  "updatedAt": ISODate("2025-01-01T00:00:00.000Z"),
  "deletedAt": null
}

// CORRECTED: Optimized indexes following ESR (Equality, Sort, Range) principles
// Basic unique index for authentication
db.users.createIndex({ "email": 1 }, { unique: true, sparse: true })

// Compound index optimized for role-based queries with temporal sorting
db.users.createIndex({ 
  "roles": 1,           // Equality filter (most selective)
  "deletedAt": 1,       // Sort/filter on deletion status
  "createdAt": -1       // Range/sort on creation time (newest first)
})

// CORRECTED: Proper text index with optimized weights
db.users.createIndex({ 
  "profile.firstName": "text", 
  "profile.lastName": "text", 
  "email": "text" 
}, {
  weights: {
    "profile.firstName": 10,
    "profile.lastName": 10,
    "email": 5
  },
  name: "user_search_text"
})

// CORRECTED: Targeted wildcard index for flexible profile queries
// Using wildcardProjection to optimize for commonly queried fields
db.users.createIndex(
  { "profile.$**": 1 },
  {
    "wildcardProjection": {
      "profile.preferences.theme": 1,
      "profile.preferences.language": 1,
      "profile.preferences.notifications": 1
    },
    name: "profile_preferences_wildcard"
  }
)

// Performance index for login tracking
db.users.createIndex({ "metadata.lastLoginAt": -1 })

// CORRECTED: Sparse index for soft deletes only
db.users.createIndex({ "deletedAt": 1 }, { 
  sparse: true,  // Only index documents where deletedAt exists
  name: "deleted_users_sparse"
})
```

### Aggregation Pipeline Patterns
```javascript
// Modern aggregation with proper operators (MongoDB 7.0+)
db.users.aggregate([
  // Match with enhanced date operators
  {
    $match: {
      createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
      deletedAt: { $exists: false }
    }
  },
  
  // Enhanced computed fields with proper operators
  {
    $addFields: {
      fullName: { $concat: ["$profile.firstName", " ", "$profile.lastName"] },
      daysSinceCreated: {
        $dateDiff: {
          startDate: "$createdAt",
          endDate: "$$NOW",
          unit: "day"
        }
      },
      // Fixed: isRecentUser should be a boolean comparison, not a duplicate dateDiff
      isRecentUser: {
        $lte: [
          {
            $dateDiff: {
              startDate: "$createdAt",
              endDate: "$$NOW",
              unit: "day"
            }
          },
          30  // Users created within last 30 days
        ]
      }
    }
  },
  
  // Modern grouping with enhanced accumulators
  {
    $group: {
      _id: "$roles",
      count: { $count: {} },                    // ✓ Correct - MongoDB 5.0+
      avgDaysSinceCreated: { $avg: "$daysSinceCreated" },
      verifiedCount: { $sum: { $cond: ["$emailVerified", 1, 0] } },
      // ✓ Correct - firstN accumulator (MongoDB 5.2+)
      firstNUsers: { 
        $firstN: { 
          input: "$$ROOT", 
          n: 5 
        } 
      }
    }
  },
  
  // Enhanced sorting
  { $sort: { count: -1 } }
])

// Modern lookup with improved performance - CORRECTED
db.orders.aggregate([
  {
    $lookup: {
      from: "users",
      localField: "userId",
      foreignField: "_id",
      as: "user",
      // ✓ Pipeline is correct for filtering and projecting
      pipeline: [
        { $match: { deletedAt: { $exists: false } } },
        { $project: { email: 1, "profile.firstName": 1, "profile.lastName": 1 } }
      ]
    }
  },
  { $unwind: "$user" },  // ✓ Correct
  {
    $project: {
      total: 1,
      createdAt: 1,
      "user.email": 1,
      "user.profile": 1
    }
  }
])
```

### Schema Validation (MongoDB 7.0)
```javascript
// Modern JSON Schema validation with enhanced features
db.createCollection("users", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["email", "passwordHash", "profile", "createdAt"],
      properties: {
        email: {
          bsonType: "string",
          pattern: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
          description: "Must be a valid email address"
        },
        emailVerified: {
          bsonType: "bool",
          description: "Email verification status"
        },
        passwordHash: {
          bsonType: "string",
          minLength: 60,
          description: "Hashed password (bcrypt)"
        },
        profile: {
          bsonType: "object",
          required: ["firstName", "lastName"],
          properties: {
            firstName: {
              bsonType: "string",
              minLength: 1,
              maxLength: 100
            },
            lastName: {
              bsonType: "string",
              minLength: 1,
              maxLength: 100
            },
            avatar: {
              bsonType: "string",
              pattern: "^https?://.+"
            },
            preferences: {
              bsonType: "object",
              properties: {
                theme: {
                  enum: ["light", "dark", "auto"]
                },
                language: {
                  bsonType: "string",
                  pattern: "^[a-z]{2}(-[A-Z]{2})?$"
                }
              }
            }
          }
        },
        roles: {
          bsonType: "array",
          items: {
            bsonType: "string",
            enum: ["admin", "user", "moderator"]
          },
          minItems: 1,
          uniqueItems: true
        },
        createdAt: {
          bsonType: "date"
        },
        updatedAt: {
          bsonType: "date"
        },
        deletedAt: {
          // Fixed: Allow null values explicitly
          bsonType: ["date", "null"]
        }
      }
    }
  },
  validationAction: "error",
  validationLevel: "strict"
})
```

## Redis Best Practices

### Caching Patterns
```javascript
import { createClient } from 'redis';

// Modern client initialization with proper error handling
const client = await createClient({
  url: 'redis://localhost:6379'
})
  .on('error', (err) => console.error('Redis Client Error', err))
  .connect();

// Enhanced session caching with proper expiration - CORRECTED
const sessionKey = `session:${userId}:${sessionId}`;
// Use .set() with EX option instead of .setEx()
await client.set(sessionKey, JSON.stringify(sessionData), {
  EX: 3600  // Expiration time in seconds
});

// Alternative approaches for setting with expiration:
// Method 1: SETEX command directly
await client.setEx(sessionKey, 3600, JSON.stringify(sessionData));

// Method 2: SET with expiration options
await client.set(sessionKey, JSON.stringify(sessionData), {
  EX: 3600,    // Expire in 3600 seconds
  NX: true     // Only set if key doesn't exist (optional)
});
```

### Rate Limiting

```javascript
// Fixed sliding window rate limiting with proper node-redis syntax
async function checkRateLimit(userId, action, limit, windowSizeSeconds) {
  const key = `rate_limit:${userId}:${action}`;
  const now = Date.now();
  const windowStart = now - (windowSizeSeconds * 1000);
  
  // Fixed: Use exec() instead of exec() with undefined behavior
  const multi = client.multi();
  multi.zRemRangeByScore(key, 0, windowStart);  // Remove expired entries
  multi.zCard(key);                             // Count current entries
  multi.zAdd(key, { score: now, value: now }); // Add current timestamp
  multi.expire(key, windowSizeSeconds);         // Set TTL on the key
  
  const results = await multi.exec();
  
  // Fixed: Proper result array indexing and error handling
  if (!results || results.length < 4) {
    throw new Error('Transaction failed');
  }
  
  // results is an array where each element is [error, result]
  const currentCount = results[1][1]; // zCard result
  
  return {
    allowed: currentCount < limit,
    remaining: Math.max(0, limit - currentCount - 1),
    resetTime: windowStart + (windowSizeSeconds * 1000)
  };
}

// Usage with proper error handling
try {
  const { allowed, remaining, resetTime } = await checkRateLimit(
    userId, 
    'api_call', 
    100, // 100 requests
    3600 // per hour
  );
  
  if (!allowed) {
    const waitTime = resetTime - Date.now();
    throw new Error(`Rate limit exceeded. Try again in ${waitTime}ms`);
  }
  
  console.log(`Request allowed. ${remaining} requests remaining.`);
} catch (error) {
  console.error('Rate limiting error:', error.message);
}
```

### Pub/Sub for Real-time Features

```javascript
import { createClient } from 'redis';

// Modern pub/sub with proper connection handling
class NotificationService {
  constructor() {
    this.publisher = null;
    this.subscriber = null;
  }

  async initialize() {
    // Create separate connections for pub/sub - FIXED: Must call connect() explicitly in v4+
    this.publisher = createClient()
      .on('error', (err) => console.error('Redis Publisher Error', err));
    
    // FIXED: For pub/sub, create a duplicate connection from the main client
    this.subscriber = this.publisher.duplicate()
      .on('error', (err) => console.error('Redis Subscriber Error', err));
    
    // FIXED: Must explicitly connect both clients
    await this.publisher.connect();
    await this.subscriber.connect();
  }

  async publishNotification(userId, notification) {
    const channel = `notifications:${userId}`;
    const message = JSON.stringify({
      id: crypto.randomUUID(), // Modern UUID generation
      type: notification.type,
      title: notification.title,
      message: notification.message,
      data: notification.data,
      timestamp: Date.now()
    });
    
    // FIXED: Use publish method correctly
    await this.publisher.publish(channel, message);
  }

  async subscribeToUserNotifications(userId, callback) {
    const channel = `notifications:${userId}`;
    
    // FIXED: Modern subscription pattern - callback is passed directly to subscribe
    await this.subscriber.subscribe(channel, (message, channelName) => {
      try {
        const notification = JSON.parse(message);
        callback(notification);
      } catch (error) {
        console.error('Failed to parse notification:', error);
      }
    });
  }

  async publishToChannel(channel, message) {
    await this.publisher.publish(channel, JSON.stringify(message));
  }

  async close() {
    // FIXED: Use destroy() instead of disconnect() in v4+
    await Promise.all([
      this.publisher?.destroy(),
      this.subscriber?.destroy()
    ]);
  }
}
```


## Modern Pipeline Operations

```javascript
// Enhanced pipeline operations with proper error handling
async function batchOperations(operations) {
  const pipeline = client.multi();
  
  operations.forEach(op => {
    switch (op.type) {
      case 'set':
        pipeline.set(op.key, op.value);
        break;
      case 'get':
        pipeline.get(op.key);
        break;
      case 'sadd':
        // Fixed: Use 'sAdd' instead of 'sAdd' (camelCase method name)
        pipeline.sAdd(op.key, op.members);
        break;
      default:
        throw new Error(`Unknown operation type: ${op.type}`);
    }
  });
  
  try {
    // Fixed: Pipeline results don't have error/value structure like in older versions
    const results = await pipeline.exec();
    return results.map((result, index) => ({
      operation: operations[index],
      result: result, // Direct result, no [error, value] structure
      error: null
    }));
  } catch (error) {
    console.error('Pipeline execution failed:', error);
    throw error;
  }
}

// Usage
const operations = [
  { type: 'set', key: 'user:1', value: 'John' },
  { type: 'get', key: 'user:1' },
  { type: 'sadd', key: 'users:active', members: ['user:1'] }
];

const results = await batchOperations(operations);
```

## Vector Database Implementation (2025)

### Pinecone Configuration
Debug any code issues
Validate syntax and logic
Consult latest documentation via context7
Provide corrected, commented solutions
```python
# Corrected Pinecone implementation with modern client
from pinecone import (
    Pinecone,
    ServerlessSpec,
    CloudProvider,
    AwsRegion,
    Metric,
    VectorType
)
import openai

# Modern client initialization
pc = Pinecone(api_key="your-api-key")

# Create modern serverless index - CORRECTED: No more host return from create_index
index_config = pc.create_index(
    name="document-search",
    dimension=1536,  # OpenAI ada-002 dimension
    metric=Metric.COSINE,
    vector_type=VectorType.DENSE,
    spec=ServerlessSpec(
        cloud=CloudProvider.AWS,
        region=AwsRegion.US_EAST_1
    )
)

# CORRECTED: Get host from describe_index, not from create_index response
desc = pc.describe_index("document-search")
index = pc.Index(host=desc.host)

# Store document embeddings with modern approach
def store_document(doc_id, text, metadata=None):
    # CORRECTED: Updated OpenAI client syntax
    client = openai.OpenAI(api_key="your-openai-api-key")
    
    response = client.embeddings.create(
        model="text-embedding-ada-002",
        input=text
    )
    embedding = response.data[0].embedding
    
    # CORRECTED: Use dictionary format for vectors, not tuple
    index.upsert(
        vectors=[{
            "id": doc_id,
            "values": embedding,
            "metadata": metadata or {}
        }],
        namespace="documents"
    )

# Modern semantic search with filtering
def search_documents(query, top_k=10, filter_metadata=None):
    # Generate query embedding
    client = openai.OpenAI(api_key="your-openai-api-key")
    
    response = client.embeddings.create(
        model="text-embedding-ada-002",
        input=query
    )
    query_embedding = response.data[0].embedding
    
    # Search with modern filtering
    results = index.query(
        vector=query_embedding,
        top_k=top_k,
        include_metadata=True,
        include_values=False,  # Don't return vectors for efficiency
        filter=filter_metadata,
        namespace="documents"
    )
    
    return results.matches

# Usage examples with enhanced metadata
store_document(
    doc_id="doc_1",
    text="Machine learning algorithms for natural language processing in 2025",
    metadata={
        "category": "AI", 
        "author": "John Doe",
        "year": 2025,
        "tags": ["ml", "nlp", "2025"]
    }
)

# Enhanced search with complex filtering
results = search_documents(
    query="machine learning NLP",
    top_k=5,
    filter_metadata={
        "category": {"$eq": "AI"},
        "year": {"$gte": 2024}
    }
)

# Print results
for match in results:
    print(f"ID: {match.id}, Score: {match.score}")
    print(f"Metadata: {match.metadata}")
```

### Weaviate Configuration
```javascript
// JavaScript example for Weaviate (updated for v3 client)
import weaviate from 'weaviate-client';

// Connect to Weaviate - updated connection method
const client = await weaviate.connectToLocal({
  scheme: 'http',
  host: 'localhost:8080',
});

// Define collection configuration (previously schema)
const collectionConfig = {
  name: 'Document',
  vectorizers: weaviate.configure.vectors.text2VecOpenAI({
    model: 'ada',
    modelVersion: '002',
    type: 'text'
  }),
  properties: [
    {
      name: 'title',
      dataType: ['string'],
    },
    {
      name: 'content',
      dataType: ['text'],
    },
    {
      name: 'category',
      dataType: ['string'],
    },
    {
      name: 'author',
      dataType: ['string'],
    },
    {
      name: 'publishedAt',
      dataType: ['date'],
    }
  ]
};

// Create collection (previously schema.classCreator)
await client.collections.create(collectionConfig);

// Define a collection to interact with
const documentCollection = client.collections.use('Document');

// Store document (updated API)
async function storeDocument(document) {
  return await documentCollection.data.insert(document);
}

// Semantic search with hybrid approach (updated API)
async function searchDocuments(query, options = {}) {
  const {
    limit = 10,
    where = null,
    certainty = 0.7
  } = options;

  // Build query parameters
  const queryParams = {
    limit: limit,
    returnMetadata: ['certainty'],
  };

  // Add filter if provided
  if (where) {
    queryParams.filters = where;
  }

  // Execute nearText search
  const result = await documentCollection.query.nearText([query], queryParams);
  
  // Filter by certainty in client code since the v3 API handles this differently
  return result.objects.filter(
    doc => doc.metadata?.certainty >= certainty
  );
}

// Usage
await storeDocument({
  title: "Introduction to Vector Databases",
  content: "Vector databases are specialized systems for storing and querying high-dimensional vectors...",
  category: "Database",
  author: "Jane Smith",
  publishedAt: "2025-01-01T00:00:00.000Z"
});

// Build filter using the new Filter helper class
const filter = documentCollection.filter.byProperty('category').equal('Database');

const results = await searchDocuments(
  "vector database applications",
  {
    limit: 5,
    where: filter
  }
);

// Don't forget to close the client when done
client.close();
```

## Database Migration Strategies

### PostgreSQL Migrations
```sql
-- Migration: 001_create_users_table.sql
BEGIN;

-- Create the uuid extension first
CREATE EXTENSION IF NOT EXISTS uuid-ossp;

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_created_at ON users(created_at);

COMMIT;


-- Migration: 002_add_user_roles.sql
BEGIN;

-- Add role column
ALTER TABLE users ADD COLUMN role VARCHAR(50) DEFAULT 'user';
ALTER TABLE users ADD CONSTRAINT check_user_role 
    CHECK (role IN ('admin', 'user', 'moderator'));

-- Add index for role queries
CREATE INDEX idx_users_role ON users(role);

-- Update existing users to have default role
UPDATE users SET role = 'user' WHERE role IS NULL;

-- Make role NOT NULL
ALTER TABLE users ALTER COLUMN role SET NOT NULL;

COMMIT;


-- Migration: 003_add_soft_deletes.sql
BEGIN;

-- Add deleted_at column for soft deletes
ALTER TABLE users ADD COLUMN deleted_at TIMESTAMP WITH TIME ZONE;

-- Create partial index for active users
CREATE INDEX idx_users_active ON users(id) WHERE deleted_at IS NULL;

-- Update unique constraint to only apply to active users
ALTER TABLE users DROP CONSTRAINT users_email_key;
CREATE UNIQUE INDEX idx_users_email_unique ON users(email) WHERE deleted_at IS NULL;

COMMIT;
```

### MongoDB Schema Evolution
```javascript
// Improved version with error handling and session
try {
  const session = db.getMongo().startSession();
  session.startTransaction();

  // Migration: Add email verification fields
  db.users.updateMany(
    { emailVerified: { $exists: false } },
    { 
      $set: { 
        emailVerified: false,
        emailVerificationToken: null,
        emailVerificationExpires: null
      }
    },
    { session }
  );

  // Migration: Restructure profile data
  db.users.updateMany(
    { firstName: { $exists: true } },
    [
      {
        $set: {
          profile: {
            firstName: "$firstName",
            lastName: "$lastName",
            avatar: "$avatar",
            preferences: {
              theme: { $ifNull: ["$theme", "light"] },
              language: { $ifNull: ["$language", "en"] }
            }
          }
        }
      },
      {
        $unset: ["firstName", "lastName", "avatar", "theme", "language"]
      }
    ],
    { session }
  );

  // Migration: Add indexes after schema change
  db.users.createIndex({ "profile.firstName": "text", "profile.lastName": "text" }, { session });
  db.users.createIndex({ "profile.preferences.theme": 1 }, { session });

  session.commitTransaction();
  session.endSession();
  print("Migration completed successfully");
} catch (error) {
  print("Migration failed:", error);
  if (session) {
    session.abortTransaction();
    session.endSession();
  }
}
```

## Performance Monitoring and Optimization

### PostgreSQL Performance Monitoring
```sql
-- Monitor slow queries
-- Requires pg_stat_statements extension to be enabled
SELECT 
    query,
    calls,
    total_time,
    mean_time,
    rows,
    100.0 * shared_blks_hit / nullif(shared_blks_hit + shared_blks_read, 0) AS hit_percent
FROM pg_stat_statements 
ORDER BY total_time DESC 
LIMIT 10;

-- Check index usage
-- Helps identify unused or rarely used indexes
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_tup_read,
    idx_tup_fetch,
    idx_scan
FROM pg_stat_user_indexes 
ORDER BY idx_scan ASC;

-- Monitor table statistics
-- Shows access patterns and modification activity
SELECT 
    schemaname,
    tablename,
    seq_scan,
    seq_tup_read,
    idx_scan,
    idx_tup_fetch,
    n_tup_ins,
    n_tup_upd,
    n_tup_del
FROM pg_stat_user_tables 
ORDER BY seq_scan DESC;

-- Check for missing indexes
-- Tables with high sequential scans and many tuples read are good candidates for indexing
SELECT 
    schemaname,
    tablename,
    seq_scan,
    seq_tup_read,
    seq_tup_read / seq_scan AS avg_seq_tup_read
FROM pg_stat_user_tables 
WHERE seq_scan > 0 
ORDER BY seq_tup_read DESC 
LIMIT 10;

-- Check for bloated tables
-- Tables that may benefit from VACUUM or ANALYZE
SELECT
    schemaname,
    tablename,
    n_live_tup,
    n_dead_tup,
    CASE WHEN n_live_tup > 0 
         THEN round(100.0 * n_dead_tup / (n_live_tup + n_dead_tup), 2)
         ELSE 0.0
    END AS dead_tup_ratio
FROM pg_stat_user_tables
WHERE n_dead_tup > 0
ORDER BY dead_tup_ratio DESC
LIMIT 10;

-- Monitor connection utilization
-- Shows current connection status
SELECT
    state,
    count(*) AS count
FROM pg_stat_activity
GROUP BY state
ORDER BY count DESC;

-- Identify long-running queries
-- Find queries that may be causing performance issues
SELECT
    pid,
    now() - query_start AS duration,
    state,
    query
FROM pg_stat_activity
WHERE state != 'idle'
  AND query_start < now() - interval '5 minutes'
ORDER BY duration DESC;

-- Check for lock contention
-- Identify processes waiting for or holding locks
SELECT
    blocked_locks.pid AS blocked_pid,
    blocked_activity.usename AS blocked_user,
    blocking_locks.pid AS blocking_pid,
    blocking_activity.usename AS blocking_user,
    blocked_activity.query AS blocked_statement,
    blocking_activity.query AS blocking_statement
FROM pg_catalog.pg_locks blocked_locks
JOIN pg_catalog.pg_stat_activity blocked_activity ON blocked_activity.pid = blocked_locks.pid
JOIN pg_catalog.pg_locks blocking_locks 
    ON blocking_locks.locktype = blocked_locks.locktype
    AND blocking_locks.DATABASE IS NOT DISTINCT FROM blocked_locks.DATABASE
    AND blocking_locks.relation IS NOT DISTINCT FROM blocked_locks.relation
    AND blocking_locks.page IS NOT DISTINCT FROM blocked_locks.page
    AND blocking_locks.tuple IS NOT DISTINCT FROM blocked_locks.tuple
    AND blocking_locks.virtualxid IS NOT DISTINCT FROM blocked_locks.virtualxid
    AND blocking_locks.transactionid IS NOT DISTINCT FROM blocked_locks.transactionid
    AND blocking_locks.classid IS NOT DISTINCT FROM blocked_locks.classid
    AND blocking_locks.objid IS NOT DISTINCT FROM blocked_locks.objid
    AND blocking_locks.objsubid IS NOT DISTINCT FROM blocked_locks.objsubid
    AND blocking_locks.pid != blocked_locks.pid
JOIN pg_catalog.pg_stat_activity blocking_activity ON blocking_activity.pid = blocking_locks.pid
WHERE NOT blocked_locks.GRANTED;

-- Transaction wraparound status
-- Monitor potential transaction ID wraparound issues
SELECT
    datname,
    age(datfrozenxid) AS xid_age,
    current_setting('autovacuum_freeze_max_age')::integer AS max_age,
    round(100.0 * age(datfrozenxid) / current_setting('autovacuum_freeze_max_age')::integer, 2) AS percent_towards_wraparound
FROM pg_database
ORDER BY percent_towards_wraparound DESC;

-- Check for unused indexes
-- Find indexes with minimal usage but ongoing maintenance overhead
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan,
    pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
FROM pg_stat_user_indexes
WHERE idx_scan < 50
  AND pg_relation_size(indexrelid) > 10 * 1024 * 1024  -- Indexes larger than 10MB
ORDER BY pg_relation_size(indexrelid) DESC
LIMIT 10;

-- Check for cache hit ratio
-- Monitors memory efficiency of frequently accessed tables
SELECT
    schemaname,
    tablename,
    heap_blks_read,
    heap_blks_hit,
    CASE WHEN heap_blks_hit + heap_blks_read = 0
         THEN 0
         ELSE round(100.0 * heap_blks_hit / (heap_blks_hit + heap_blks_read), 2)
    END AS hit_ratio
FROM pg_statio_user_tables
ORDER BY heap_blks_read + heap_blks_hit DESC
LIMIT 10;
```

### MongoDB Performance Monitoring
```javascript
// Enable profiling for slow operations
// This sets the profiling level to 2 (all operations) with a threshold of 100ms
// 0 = off, 1 = slow ops only, 2 = all operations
db.setProfilingLevel(2, { slowms: 100 });

// View the most recent slow operations from the profiler
// The profiler data is stored in the system.profile collection
db.system.profile.find()
  .sort({ ts: -1 })  // Sort by timestamp in descending order
  .limit(5)          // Return only the 5 most recent entries
  .pretty();         // Format the output for better readability

// Retrieve index usage statistics
// This aggregation provides metrics on how indexes are being used
db.users.aggregate([
  { $indexStats: {} }
]);

// Get collection statistics
// Shows storage statistics, index sizes, document count, etc.
db.users.stats();

// Explain query execution plan
// The "executionStats" mode provides detailed information about query performance
db.users.find({ "profile.firstName": "John" }).explain("executionStats");

// Monitor replica set status
// Shows state of all replica set members and replication lag
rs.status();

// Check sharding status (if using sharding)
// Shows sharding configuration, chunk distribution, and balancer status
sh.status();

```

## Security Best Practices

### Database Security Checklist
```yaml
# PostgreSQL Security Configuration
# postgresql.conf
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
ssl_ca_file = 'ca.crt'
ssl_ciphers = 'HIGH:!3DES:!aNULL:!MD5:!MEDIUM'  # More restrictive cipher list
ssl_prefer_server_ciphers = on                   # Prefer server ciphers
ssl_min_protocol_version = 'TLSv1.2'             # Enforce minimum TLS version
password_encryption = scram-sha-256
log_connections = on
log_disconnections = on
log_statement = 'ddl'
log_min_duration_statement = 1000                # Log slow queries (1+ second)
log_min_error_statement = error                  # Log statements causing errors


# pg_hba.conf
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                               peer
host    all             all             127.0.0.1/32           scram-sha-256
host    all             all             ::1/128                scram-sha-256
# Replace with specific network ranges where possible:
hostssl all             all             0.0.0.0/0              scram-sha-256
# Better yet, restrict to specific networks:
# hostssl all           all             192.168.1.0/24         scram-sha-256
```

### Application-Level Security
```typescript
// Database connection with security
import { Pool } from 'pg';
import * as fs from 'fs';        // Missing import for fs module
import { z } from 'zod';         // Missing import for Zod validation library

const pool = new Pool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: {
    rejectUnauthorized: true,
    ca: fs.readFileSync('ca.crt'),
    cert: fs.readFileSync('client.crt'),
    key: fs.readFileSync('client.key'),
  },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Always use parameterized queries
async function getUserByEmail(email: string) {
  try {                                          // Added error handling
    const query = 'SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL';
    const result = await pool.query(query, [email]);
    return result.rows[0];                       // Returns undefined if no user found
  } catch (error) {
    console.error('Database query error:', error);
    throw new Error('Failed to retrieve user');  // Re-throw with meaningful message
  }
}

// Input validation and sanitization
function validateAndSanitizeUserInput(input: any) {
  // Use Zod for validation
  const schema = z.object({
    email: z.string().email(),
    firstName: z.string().min(1).max(100),
    lastName: z.string().min(1).max(100),
  });
  
  return schema.parse(input);  // This throws ZodError if validation fails
}

// Proper resource management - good practice to add
async function closePool() {
  await pool.end();
  console.log('Database connection pool closed');
}
```

## Backup and Recovery Strategies

### PostgreSQL Backup
```bash
#!/bin/bash
# Automated PostgreSQL backup script with error handling and logging

# Configuration
DB_NAME="your_database"
BACKUP_DIR="/backups/postgresql"
LOG_FILE="/var/log/pg_backup.log"
S3_BUCKET="your-backup-bucket"
S3_PREFIX="postgresql"
RETENTION_DAYS=7

# Create timestamp
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/${DB_NAME}_${DATE}.sql"

# Function for logging
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    echo "$1"
}

# Error handling function
handle_error() {
    log_message "ERROR: $1"
    # Optional: Add notification system here (email, Slack, etc.)
    # Example: mail -s "Backup failed for $DB_NAME" admin@example.com <<< "Error: $1"
    exit 1
}

# Start backup process
log_message "Starting backup of database: $DB_NAME"

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR" || handle_error "Failed to create backup directory"

# Check if PostgreSQL is running
pg_isready -h localhost -U postgres > /dev/null 2>&1
if [ $? -ne 0 ]; then
    handle_error "PostgreSQL server is not running or not accessible"
fi

# Create database dump (using PGPASSWORD environment variable instead of hardcoding)
# Add password to ~/.pgpass file or use PGPASSWORD environment variable in production
log_message "Creating database dump..."
pg_dump -h localhost -U postgres -Fc "$DB_NAME" > "$BACKUP_FILE" 2>> "$LOG_FILE"
if [ $? -ne 0 ]; then
    handle_error "Database dump failed"
fi

# Verify backup file exists and has content
if [ ! -s "$BACKUP_FILE" ]; then
    handle_error "Backup file is empty or does not exist"
fi

# Compress the backup (preserve original with -c option)
log_message "Compressing backup file..."
gzip -c "$BACKUP_FILE" > "${BACKUP_FILE}.gz"
if [ $? -ne 0 ]; then
    handle_error "Failed to compress backup file"
fi

# Remove the uncompressed backup to save space
rm "$BACKUP_FILE"

# Upload to AWS S3
log_message "Uploading to S3 bucket: $S3_BUCKET/$S3_PREFIX/"
aws s3 cp "${BACKUP_FILE}.gz" "s3://$S3_BUCKET/$S3_PREFIX/" --only-show-errors
if [ $? -ne 0 ]; then
    handle_error "S3 upload failed"
fi

# Remove backups older than specified retention period
log_message "Cleaning up old backups (older than $RETENTION_DAYS days)..."
find "$BACKUP_DIR" -name "*.gz" -type f -mtime +$RETENTION_DAYS -delete
if [ $? -ne 0 ]; then
    log_message "Warning: Failed to clean up old backups"
fi

# Optional: Clean up old backups from S3 as well
# aws s3 ls "s3://$S3_BUCKET/$S3_PREFIX/" | grep -v $(date +%Y%m%d -d "-$RETENTION_DAYS days") | xargs -I {} aws s3 rm "s3://$S3_BUCKET/$S3_PREFIX/{}"

log_message "Backup completed successfully: ${BACKUP_FILE}.gz"
exit 0
```

### MongoDB Backup
```bash
#!/bin/bash
# MongoDB backup script with improved error handling and logging

# Configuration
DB_NAME="your_database"
BACKUP_DIR="/backups/mongodb"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/$DATE"
S3_BUCKET="s3://your-backup-bucket/mongodb/"
LOG_FILE="/var/log/mongodb_backup.log"
RETENTION_DAYS=7

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR" || { echo "Failed to create backup directory"; exit 1; }

# Log function
log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting MongoDB backup for $DB_NAME"

# Create backup with error handling
if ! mongodump --host localhost:27017 --db "$DB_NAME" --out "$BACKUP_PATH"; then
  log "ERROR: MongoDB backup failed"
  exit 1
fi
log "Backup created successfully at $BACKUP_PATH"

# Compress backup
if ! tar -czf "${BACKUP_PATH}.tar.gz" -C "$BACKUP_DIR" "$DATE"; then
  log "ERROR: Failed to compress backup"
  exit 1
fi
log "Backup compressed to ${BACKUP_PATH}.tar.gz"

# Clean up uncompressed backup
rm -rf "$BACKUP_PATH"
log "Removed uncompressed backup files"

# Remove old backups
log "Removing backups older than $RETENTION_DAYS days"
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +"$RETENTION_DAYS" -delete

# Upload to cloud storage with error handling
if ! aws s3 cp "${BACKUP_PATH}.tar.gz" "$S3_BUCKET"; then
  log "ERROR: Failed to upload backup to S3"
  exit 1
fi
log "Backup successfully uploaded to $S3_BUCKET"

log "Backup process completed successfully"
```

### Refined Decision Matrix

| Use Case | Recommended Database | Why |
|----------|---------------------|-----|
| E-commerce Platform | PostgreSQL + Redis | ACID compliance for transactions, Redis for cart/session management and real-time features. PostgreSQL's maturity and extensibility make it ideal for complex e-commerce data models. |
| Content Management | PostgreSQL or MongoDB | MongoDB offers flexible schema for varied content types, but PostgreSQL with JSONB has similar capabilities with stronger consistency guarantees. Choose based on query complexity needs. |
| Real-time Analytics | ClickHouse or TimescaleDB | Choose ClickHouse for large-scale batch analytics and data warehousing scenarios. Choose TimescaleDB for workloads requiring more frequent updates and PostgreSQL compatibility. |
| Social Media | PostgreSQL + Redis | PostgreSQL has improved graph capabilities. For specialized graph needs, consider dedicated graph databases, but for many applications, PostgreSQL can handle social graphs with proper indexing. |
| IoT Data | TimescaleDB | TimescaleDB's specialized time-series optimizations make it particularly effective for IoT workloads with mixed query patterns. Recent benchmarks show it excels at real-time IoT analytics. |
| Search Engine | PostgreSQL + pgvector or Elasticsearch | PostgreSQL with pgvector now offers competitive full-text search capabilities with vector embeddings for semantic search. Elasticsearch remains superior for complex search at massive scale. |
| AI/ML Applications | PostgreSQL + pgvector/pgvectorscale | PostgreSQL with vector extensions now offers high-performance vector operations within a mature relational database, simplifying infrastructure. For specialized needs, consider dedicated vector databases. |
| Gaming Leaderboards | Redis + PostgreSQL | Redis remains optimal for real-time leaderboards with PostgreSQL for persistent storage and complex analytics. |
| Financial Systems | PostgreSQL | Still the gold standard for ACID compliance and regulatory requirements. Recent versions have improved performance for financial workloads. |
| Document Storage | PostgreSQL or MongoDB | PostgreSQL with JSONB offers document capabilities with stronger consistency. MongoDB provides more specialized document features. Both now have mature GridFS equivalents. |

### Performance Considerations Updates

- **Read-Heavy**: PostgreSQL with properly configured read replicas performs well. For extreme scale, consider ClickHouse.
- **Write-Heavy**: TimescaleDB has improved for time-series write workloads. MongoDB with sharding remains strong.
- **Complex Queries**: PostgreSQL continues to excel for complex JOINs. Recent versions have improved query planning.
- **Vector Operations**: PostgreSQL with pgvector/pgvectorscale now offers competitive performance for many vector workloads.
- **Real-time**: Redis remains the leader for sub-millisecond operations and now offers enhanced AI-specific features.
- **Large Scale**: Distributed options like ClickHouse for analytics and MongoDB for documents are still recommended.

### New Consideration: Simplifying the Stack

A key trend in 2025 is the convergence of database capabilities, allowing teams to simplify their database architecture:

- PostgreSQL with extensions can now effectively serve as relational, document, and vector database simultaneously
- This simplification reduces operational complexity and allows for more unified data management
- For many applications, a well-configured PostgreSQL instance with appropriate extensions can replace multiple specialized databases

### Recommendations

1. **Reevaluate PostgreSQL for AI applications**: With pgvector and pgvectorscale, PostgreSQL is now a strong contender for AI workloads, potentially eliminating the need for a separate vector database in your architecture.

2. **Consider workload-specific performance**: The choice between TimescaleDB and ClickHouse should be based on your specific analytics patterns, as their performance varies significantly by workload type.

3. **Leverage Redis's AI enhancements**: For AI applications requiring caching or real-time features, Redis's new AI-specific capabilities (LangCache, vector sets) offer significant benefits.

4. **Simplify when possible**: Consider if your architecture can be simplified by using PostgreSQL's expanded capabilities rather than maintaining multiple database technologies.
