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

-- Advanced JSONB path queries (PostgreSQL 17)
CREATE INDEX idx_preferences_theme ON user_preferences 
USING BTREE((preferences->>'theme')) WHERE preferences ? 'theme';

-- JSON path expression indexes
CREATE INDEX idx_preferences_notifications ON user_preferences 
USING GIN((preferences @? '$.notifications.**'));

-- Composite indexes with include columns (PostgreSQL 11+)
CREATE INDEX idx_users_role_created_include ON users(role, created_at) 
INCLUDE (first_name, last_name) WHERE deleted_at IS NULL;
```

### Database Triggers and Functions
```sql
-- Modern trigger function with better error handling
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER 
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

-- Apply trigger to tables
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Advanced audit log function with JSONB
CREATE OR REPLACE FUNCTION create_audit_log()
RETURNS TRIGGER 
LANGUAGE plpgsql
AS $$
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
        COALESCE(NEW.updated_by, OLD.updated_by),
        NOW()
    );
    RETURN COALESCE(NEW, OLD);
END;
$$;
```

### Query Optimization Patterns
```sql
-- Modern query optimization with EXPLAIN
EXPLAIN (ANALYZE, BUFFERS, VERBOSE, SETTINGS) 
SELECT u.*, p.preferences 
FROM users u 
LEFT JOIN user_preferences p ON u.id = p.user_id 
WHERE u.role = 'user' 
    AND u.created_at > NOW() - INTERVAL '30 days'
    AND u.deleted_at IS NULL
ORDER BY u.created_at DESC 
LIMIT 20;

-- Efficient pagination with improved cursor approach
SELECT * FROM users 
WHERE (created_at, id) < ($1, $2)  -- composite cursor
    AND deleted_at IS NULL
ORDER BY created_at DESC, id DESC
LIMIT 20;

-- Modern full-text search with ranking
SELECT *, 
       ts_rank(search_vector, websearch_to_tsquery('english', $1)) as rank
FROM users 
WHERE search_vector @@ websearch_to_tsquery('english', $1)
    AND deleted_at IS NULL
ORDER BY rank DESC, created_at DESC
LIMIT 20;

-- Enhanced CTEs with materialization control
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
// Enhanced user document schema with time series support
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

// Modern indexes for performance
db.users.createIndex({ "email": 1 }, { unique: true, sparse: true })
db.users.createIndex({ "roles": 1 })
db.users.createIndex({ "createdAt": 1 })
db.users.createIndex({ "deletedAt": 1 }, { sparse: true })

// Enhanced text index with weights
db.users.createIndex({ 
  "profile.firstName": "text", 
  "profile.lastName": "text", 
  "email": "text" 
}, {
  weights: {
    "profile.firstName": 10,
    "profile.lastName": 10,
    "email": 5
  }
})

// Modern compound indexes for complex queries
db.users.createIndex({ 
  "roles": 1, 
  "createdAt": -1, 
  "deletedAt": 1 
})

// Wildcard indexes for flexible queries (MongoDB 4.2+)
db.users.createIndex({ "profile.$**": 1 })
```

### Aggregation Pipeline Patterns
```javascript
// Modern aggregation with new operators (MongoDB 7.0+)
db.users.aggregate([
  // Match with enhanced date operators
  {
    $match: {
      createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
      deletedAt: { $exists: false }
    }
  },
  
  // Enhanced computed fields with new operators
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
      isRecentUser: {
        $dateDiff: {
          startDate: "$createdAt",
          endDate: "$$NOW",
          unit: "day"
        }
      }
    }
  },
  
  // Modern grouping with enhanced accumulators
  {
    $group: {
      _id: "$roles",
      count: { $count: {} },
      avgDaysSinceCreated: { $avg: "$daysSinceCreated" },
      verifiedCount: { $sum: { $cond: ["$emailVerified", 1, 0] } },
      // New accumulator in MongoDB 7.0
      firstNUsers: { $firstN: { input: "$$ROOT", n: 5 } }
    }
  },
  
  // Enhanced sorting
  { $sort: { count: -1 } }
])

// Modern lookup with improved performance
db.orders.aggregate([
  {
    $lookup: {
      from: "users",
      localField: "userId",
      foreignField: "_id",
      as: "user",
      pipeline: [
        { $match: { deletedAt: { $exists: false } } },
        { $project: { email: 1, "profile.firstName": 1, "profile.lastName": 1 } }
      ]
    }
  },
  { $unwind: "$user" },
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

// Enhanced session caching with proper expiration
const sessionKey = `session:${userId}:${sessionId}`;
await client.setEx(sessionKey, 3600, JSON.stringify(sessionData)); // Modern approach
```

### Rate Limiting
```javascript
// Modern sliding window rate limiting with improved error handling
async function checkRateLimit(userId, action, limit, windowSizeSeconds) {
  const key = `rate_limit:${userId}:${action}`;
  const now = Date.now();
  const windowStart = now - (windowSizeSeconds * 1000);
  
  // Use modern pipeline approach
  const pipeline = client.multi();
  pipeline.zRemRangeByScore(key, 0, windowStart);
  pipeline.zCard(key);
  pipeline.zAdd(key, { score: now, value: now });
  pipeline.expire(key, windowSizeSeconds);
  
  const results = await pipeline.exec();
  const currentCount = results[1][1];
  
  return {
    allowed: currentCount < limit,
    remaining: Math.max(0, limit - currentCount - 1),
    resetTime: windowStart + (windowSizeSeconds * 1000)
  };
}

// Usage with modern async/await
const { allowed, remaining } = await checkRateLimit(
  userId, 
  'api_call', 
  100, // 100 requests
  3600 // per hour
);

if (!allowed) {
  throw new Error(`Rate limit exceeded. Try again in ${resetTime - Date.now()}ms`);
}
```

### Pub/Sub for Real-time Features
```javascript
// Modern pub/sub with proper connection handling
class NotificationService {
  constructor() {
    this.publisher = null;
    this.subscriber = null;
  }

  async initialize() {
    // Create separate connections for pub/sub
    this.publisher = await createClient()
      .on('error', (err) => console.error('Redis Publisher Error', err))
      .connect();

    this.subscriber = await createClient()
      .on('error', (err) => console.error('Redis Subscriber Error', err))
      .connect();
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
    
    await this.publisher.publish(channel, message);
  }

  async subscribeToUserNotifications(userId, callback) {
    const channel = `notifications:${userId}`;
    
    // Modern subscription pattern
    await this.subscriber.subscribe(channel, (message) => {
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
    await Promise.all([
      this.publisher?.disconnect(),
      this.subscriber?.disconnect()
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
        pipeline.sAdd(op.key, op.members);
        break;
      default:
        throw new Error(`Unknown operation type: ${op.type}`);
    }
  });
  
  try {
    const results = await pipeline.exec();
    return results.map((result, index) => ({
      operation: operations[index],
      result: result[1], // result[0] is error, result[1] is value
      error: result[0]
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
```python
# Updated Pinecone implementation with modern client
from pinecone import (
    Pinecone,
    ServerlessSpec,
    CloudProvider,
    AwsRegion,
    Metric,
    VectorType
)

# Modern client initialization
pc = Pinecone(api_key="your-api-key")

# Create modern serverless index
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

# Connect to index
index = pc.Index(host=index_config.host)

# Store document embeddings with modern approach
def store_document(doc_id, text, metadata=None):
    # Use OpenAI or other embedding service
    import openai
    
    response = openai.embeddings.create(
        model="text-embedding-ada-002",
        input=text
    )
    embedding = response.data[0].embedding
    
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
    response = openai.embeddings.create(
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
results = search_documents
```

### Weaviate Configuration
```javascript
// JavaScript example for Weaviate
import weaviate from 'weaviate-ts-client';

const client = weaviate.client({
  scheme: 'http',
  host: 'localhost:8080',
});

// Define schema
const schema = {
  class: 'Document',
  vectorizer: 'text2vec-openai',
  moduleConfig: {
    'text2vec-openai': {
      model: 'ada',
      modelVersion: '002',
      type: 'text'
    }
  },
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

// Create schema
await client.schema
  .classCreator()
  .withClass(schema)
  .do();

// Store documents
async function storeDocument(document) {
  return await client.data
    .creator()
    .withClassName('Document')
    .withProperties(document)
    .do();
}

// Semantic search with hybrid approach
async function searchDocuments(query, options = {}) {
  const {
    limit = 10,
    where = null,
    certainty = 0.7
  } = options;

  let queryBuilder = client.graphql
    .get()
    .withClassName('Document')
    .withFields('title content category author publishedAt _additional { certainty }')
    .withNearText({ concepts: [query] })
    .withLimit(limit);

  if (where) {
    queryBuilder = queryBuilder.withWhere(where);
  }

  const result = await queryBuilder.do();
  
  return result.data.Get.Document.filter(
    doc => doc._additional.certainty >= certainty
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

const results = await searchDocuments(
  "vector database applications",
  {
    limit: 5,
    where: {
      path: ['category'],
      operator: 'Equal',
      valueText: 'Database'
    }
  }
);
```

## Database Migration Strategies

### PostgreSQL Migrations
```sql
-- Migration: 001_create_users_table.sql
BEGIN;

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
DROP INDEX users_email_key;
CREATE UNIQUE INDEX idx_users_email_unique ON users(email) WHERE deleted_at IS NULL;

COMMIT;
```

### MongoDB Schema Evolution
```javascript
// Migration: Add email verification fields
db.users.updateMany(
  { emailVerified: { $exists: false } },
  { 
    $set: { 
      emailVerified: false,
      emailVerificationToken: null,
      emailVerificationExpires: null
    }
  }
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
  ]
);

// Migration: Add indexes after schema change
db.users.createIndex({ "profile.firstName": "text", "profile.lastName": "text" });
db.users.createIndex({ "profile.preferences.theme": 1 });
```

## Performance Monitoring and Optimization

### PostgreSQL Performance Monitoring
```sql
-- Monitor slow queries
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
```

### MongoDB Performance Monitoring
```javascript
// Enable profiling for slow operations
db.setProfilingLevel(2, { slowms: 100 });

// View slow operations
db.system.profile.find()
  .sort({ ts: -1 })
  .limit(5)
  .pretty();

// Index usage statistics
db.users.aggregate([
  { $indexStats: {} }
]);

// Collection statistics
db.users.stats();

// Explain query execution
db.users.find({ "profile.firstName": "John" }).explain("executionStats");

// Monitor replica set status
rs.status();

// Check sharding status (if using sharding)
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
ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL'
password_encryption = scram-sha-256
log_connections = on
log_disconnections = on
log_statement = 'ddl'

# pg_hba.conf
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                               peer
host    all             all             127.0.0.1/32           scram-sha-256
host    all             all             ::1/128                scram-sha-256
hostssl all             all             0.0.0.0/0              scram-sha-256
```

### Application-Level Security
```typescript
// Database connection with security
import { Pool } from 'pg';

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
  const query = 'SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL';
  const result = await pool.query(query, [email]);
  return result.rows[0];
}

// Input validation and sanitization
function validateAndSanitizeUserInput(input: any) {
  // Use Zod or similar for validation
  const schema = z.object({
    email: z.string().email(),
    firstName: z.string().min(1).max(100),
    lastName: z.string().min(1).max(100),
  });
  
  return schema.parse(input);
}
```

## Backup and Recovery Strategies

### PostgreSQL Backup
```bash
#!/bin/bash
# Automated backup script

DB_NAME="your_database"
BACKUP_DIR="/backups/postgresql"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/${DB_NAME}_${DATE}.sql"

# Create backup directory if it doesn't exist
mkdir -p $BACKUP_DIR

# Create database dump
pg_dump -h localhost -U postgres $DB_NAME > $BACKUP_FILE

# Compress the backup
gzip $BACKUP_FILE

# Remove backups older than 7 days
find $BACKUP_DIR -name "*.gz" -mtime +7 -delete

# Upload to cloud storage (example with AWS S3)
aws s3 cp "${BACKUP_FILE}.gz" s3://your-backup-bucket/postgresql/
```

### MongoDB Backup
```bash
#!/bin/bash
# MongoDB backup script

DB_NAME="your_database"
BACKUP_DIR="/backups/mongodb"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/$DATE"

# Create backup
mongodump --host localhost:27017 --db $DB_NAME --out $BACKUP_PATH

# Compress backup
tar -czf "${BACKUP_PATH}.tar.gz" -C $BACKUP_DIR $DATE

# Clean up uncompressed backup
rm -rf $BACKUP_PATH

# Remove old backups
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete

# Upload to cloud storage
aws s3 cp "${BACKUP_PATH}.tar.gz" s3://your-backup-bucket/mongodb/
```

## Database Selection Decision Matrix

### Use Case Decision Framework

| Use Case | Recommended Database | Why |
|----------|---------------------|-----|
| E-commerce Platform | PostgreSQL + Redis | ACID compliance for transactions, Redis for cart/session |
| Content Management | MongoDB | Flexible schema for varied content types |
| Real-time Analytics | ClickHouse or TimescaleDB | Optimized for time-series and analytical queries |
| Social Media | PostgreSQL + Redis + Graph DB | Relational data + caching + social graph |
| IoT Data | InfluxDB or TimescaleDB | Time-series optimization for sensor data |
| Search Engine | Elasticsearch + PostgreSQL | Full-text search + metadata storage |
| AI/ML Applications | Vector DB + PostgreSQL | Embeddings + structured data |
| Gaming Leaderboards | Redis + PostgreSQL | Real-time scores + persistent data |
| Financial Systems | PostgreSQL | ACID compliance, regulatory requirements |
| Document Storage | MongoDB + GridFS | Document-oriented with file storage |

### Performance Considerations
- **Read-Heavy**: PostgreSQL with read replicas, MongoDB with replica sets
- **Write-Heavy**: MongoDB with sharding, Redis for very high throughput
- **Complex Queries**: PostgreSQL for complex JOINs and analytics
- **Simple Queries**: MongoDB for document-based simple queries
- **Real-time**: Redis for sub-millisecond operations
- **Large Scale**: Distributed databases (Cassandra, MongoDB sharding)
