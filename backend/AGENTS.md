# Node.js + TypeScript Backend Guidelines for AI Agents (2025)

*Place this file in your Node.js backend directory: `backend/AGENTS.md`*

## Technology Stack

- **Runtime**: Node.js 20+ with ES2022 support
- **Language**: TypeScript 5.0+ with strict mode
- **Framework**: Express.js 4.18+ with helmet and cors
- **Database**: PostgreSQL 15+ with Prisma ORM or TypeORM
- **Authentication**: JWT with RS256 algorithm and passport.js
- **Validation**: Zod for runtime type validation
- **Testing**: Jest with Supertest for API testing
- **Process Management**: PM2 for production deployment

## Project Structure

```
backend/
├── src/
│   ├── controllers/         # Route handlers and request/response logic
│   │   ├── auth.controller.ts
│   │   ├── user.controller.ts
│   │   └── index.ts
│   ├── services/           # Business logic and external integrations
│   │   ├── auth.service.ts
│   │   ├── user.service.ts
│   │   ├── email.service.ts
│   │   └── index.ts
│   ├── repositories/       # Data access layer
│   │   ├── user.repository.ts
│   │   ├── session.repository.ts
│   │   └── index.ts
│   ├── models/            # Database models and schemas
│   │   ├── user.model.ts
│   │   ├── session.model.ts
│   │   └── index.ts
│   ├── middleware/        # Express middleware
│   │   ├── auth.middleware.ts
│   │   ├── validation.middleware.ts
│   │   ├── error.middleware.ts
│   │   ├── logging.middleware.ts
│   │   └── index.ts
│   ├── routes/            # API route definitions
│   │   ├── auth.routes.ts
│   │   ├── user.routes.ts
│   │   ├── health.routes.ts
│   │   └── index.ts
│   ├── types/             # TypeScript type definitions
│   │   ├── auth.types.ts
│   │   ├── user.types.ts
│   │   ├── api.types.ts
│   │   └── index.ts
│   ├── utils/             # Utility functions and helpers
│   │   ├── logger.ts
│   │   ├── crypto.ts
│   │   ├── validation.ts
│   │   ├── response.ts
│   │   └── index.ts
│   ├── config/            # Configuration management
│   │   ├── database.ts
│   │   ├── jwt.ts
│   │   ├── redis.ts
│   │   └── index.ts
│   ├── events/            # Event emitters and handlers
│   │   ├── user.events.ts
│   │   ├── auth.events.ts
│   │   └── index.ts
│   ├── jobs/              # Background job definitions
│   │   ├── email.jobs.ts
│   │   ├── cleanup.jobs.ts
│   │   └── index.ts
│   ├── app.ts             # Express application setup
│   └── server.ts          # Server initialization
├── tests/                 # Test files
│   ├── unit/             # Unit tests
│   ├── integration/      # Integration tests
│   ├── e2e/              # End-to-end tests
│   ├── fixtures/         # Test data fixtures
│   ├── helpers/          # Test utilities
│   └── setup.ts          # Test configuration
├── migrations/           # Database migrations
├── seeds/                # Database seed data
├── docs/                 # API documentation
│   ├── openapi.yaml
│   └── README.md
├── scripts/              # Build and deployment scripts
├── .env.example          # Environment variables template
├── Dockerfile            # Container definition
├── docker-compose.yml    # Local development setup
├── tsconfig.json         # TypeScript configuration
├── jest.config.js        # Jest configuration
└── package.json          # Dependencies and scripts
```

## TypeScript Configuration

### Strict TypeScript Setup
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "Node16", // Changed from CommonJS for better ES2022 compatibility
    "moduleResolution": "Node16", // Added explicit module resolution
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true, // Added for better import compatibility
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "removeComments": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "exactOptionalPropertyTypes": true, // Added for stricter type checking
    "useUnknownInCatchVariables": true, // Added for better error handling
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"],
      "@/controllers/*": ["src/controllers/*"],
      "@/services/*": ["src/services/*"],
      "@/repositories/*": ["src/repositories/*"],
      "@/models/*": ["src/models/*"],
      "@/middleware/*": ["src/middleware/*"],
      "@/types/*": ["src/types/*"],
      "@/utils/*": ["src/utils/*"],
      "@/config/*": ["src/config/*"]
    }
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

## Express Application Setup

### Main Application Configuration
```typescript
// src/app.ts
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import { rateLimit } from 'express-rate-limit';
import { Request, Response, NextFunction } from 'express';
import { config } from '@/config';
import { logger } from '@/utils/logger';
import { errorHandler } from '@/middleware/error.middleware';
import { requestLogger } from '@/middleware/logging.middleware';
import { correlationId } from '@/middleware/correlation.middleware';
import routes from '@/routes';

// Extend Express Request type for custom properties
declare global {
  namespace Express {
    interface Request {
      correlationId: string;
      user?: {
        id: string;
        email: string;
        role: string;
      };
    }
  }
}

export function createApp(): express.Application {
  const app = express();

  // Disable X-Powered-By header for security (recommended by Helmet.js docs)
  app.disable('x-powered-by');

  // Configure trust proxy if behind a proxy/load balancer
  app.set('trust proxy', 1); // Adjust number based on your proxy setup

  // Security middleware
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
    strictTransportSecurity: {
      maxAge: 31536000, // 1 year in seconds
      includeSubDomains: true,
      preload: true,
    },
  }));

  // CORS configuration
  app.use(cors({
    origin: config.cors.origins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Correlation-ID'],
  }));

  // Rate limiting - updated configuration for latest express-rate-limit
  app.use(rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    limit: 100, // Limit each IP to 100 requests per windowMs
    message: {
      error: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests, please try again later.',
    },
    standardHeaders: 'draft-8', // Use latest draft standard for rate limit headers
    legacyHeaders: false, // Disable X-RateLimit-* headers
    // Skip function can be added for allowlists if needed
    // skip: (req, res) => allowlist.includes(req.ip),
  }));

  // Compression and parsing
  app.use(compression());
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Custom middleware
  app.use(correlationId);
  app.use(requestLogger);

  // Health check endpoint
  app.get('/health', (req: Request, res: Response) => {
    res.status(200).json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
    });
  });

  // API routes
  app.use('/api/v1', routes);

  // 404 handler
  app.use('*', (req: Request, res: Response) => {
    res.status(404).json({
      success: false,
      error: 'NOT_FOUND',
      message: `Route ${req.method} ${req.originalUrl} not found`,
    });
  });

  // Global error handler
  app.use(errorHandler);

  return app;
}
```

### Server Initialization
```typescript
// src/server.ts
import { createApp } from './app';
import { config } from '@/config';
import { logger } from '@/utils/logger';
import { connectDatabase } from '@/config/database';
import { connectRedis } from '@/config/redis';
import { Server } from 'http';

async function startServer(): Promise<void> {
  let server: Server | null = null;
  
  try {
    // Initialize database connections
    await connectDatabase();
    await connectRedis();
    
    // Create Express application
    const app = createApp();
    
    // Start server
    server = app.listen(config.port, () => {
      logger.info(`Server running on port ${config.port}`, {
        environment: config.env,
        port: config.port,
      });
    });
    
    // Graceful shutdown handler
    const gracefulShutdown = async (signal: string) => {
      logger.info(`Received ${signal}, shutting down gracefully`);
      
      if (server) {
        // Stop accepting new connections
        server.close((err) => {
          if (err) {
            logger.error('Error during server close:', { error: err });
          } else {
            logger.info('HTTP server closed');
          }
          process.exit(err ? 1 : 0);
        });
        
        // Force close after 30 seconds
        setTimeout(() => {
          logger.error('Could not close connections in time, forcefully shutting down');
          process.exit(1);
        }, 30000);
      } else {
        process.exit(0);
      }
    };
    
    // Register signal handlers
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    
  } catch (error) {
    logger.error('Failed to start server', { error });
    process.exit(1);
  }
}

// Handle unhandled promise rejections - re-throw to be caught by uncaughtException
process.on('unhandledRejection', (reason: unknown, promise: Promise<any>) => {
  logger.error('Unhandled Promise Rejection at:', { promise, reason });
  // Re-throw to be caught by uncaughtException handler
  throw reason;
});

// Handle uncaught exceptions
process.on('uncaughtException', (error: Error) => {
  logger.error('Uncaught Exception:', { error: error.message, stack: error.stack });
  // Allow graceful shutdown attempt, but exit after timeout
  setTimeout(() => {
    process.exit(1);
  }, 5000);
});

// Add process warning handler for better debugging
process.on('warning', (warning) => {
  logger.warn('Process warning:', {
    name: warning.name,
    message: warning.message,
    stack: warning.stack
  });
});

startServer();
```

## Base controller implementation with proper error handling, type safety, and Zod integration:

```typescript
// src/types/express.d.ts - Extended Request interface
import { Request } from 'express';

declare global {
  namespace Express {
    interface Request {
      correlationId?: string;
      user?: {
        id: string;
        [key: string]: any;
      };
    }
  }
}
```

```typescript
// src/types/api.types.ts - API Response types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  message: string;
  meta: {
    timestamp: string;
    correlationId?: string;
  };
  errors?: ValidationError[];
}

export interface ValidationError {
  field: string;
  message: string;
  code: string;
}
```

```typescript
// src/controllers/base.controller.ts - Corrected implementation
import { Request, Response, NextFunction } from 'express';
import { ZodSchema, ZodError } from 'zod';
import { logger } from '@/utils/logger';
import { ApiResponse, ValidationError } from '@/types/api.types';

export abstract class BaseController {
  /**
   * Execute an async operation with proper error handling
   */
  protected async executeAsync<T>(
    req: Request,
    res: Response,
    next: NextFunction,
    operation: (req: Request, res: Response) => Promise<T>
  ): Promise<void> {
    try {
      this.logOperation(req, 'Starting operation');
      const result = await operation(req, res);
      this.sendSuccess(res, result);
    } catch (error) {
      // Log the error with context
      logger.error('Controller operation failed', {
        correlationId: req.correlationId,
        userId: req.user?.id,
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });
      
      next(error);
    }
  }

  /**
   * Validate request data using Zod schema with proper error handling
   */
  protected validateRequest<T>(
    schema: ZodSchema<T>,
    data: unknown,
    fieldName = 'request'
  ): { success: true; data: T } | { success: false; errors: ValidationError[] } {
    const result = schema.safeParse(data);
    
    if (!result.success) {
      // Transform ZodError to API-friendly validation errors
      const validationErrors: ValidationError[] = result.error.errors.map((issue) => ({
        field: issue.path.length > 0 ? issue.path.join('.') : fieldName,
        message: issue.message,
        code: issue.code,
      }));

      return { success: false, errors: validationErrors };
    }

    return { success: true, data: result.data };
  }

  /**
   * Validate request body specifically
   */
  protected validateBody<T>(
    req: Request,
    schema: ZodSchema<T>
  ): { success: true; data: T } | { success: false; errors: ValidationError[] } {
    return this.validateRequest(schema, req.body, 'body');
  }

  /**
   * Validate request query parameters
   */
  protected validateQuery<T>(
    req: Request,
    schema: ZodSchema<T>
  ): { success: true; data: T } | { success: false; errors: ValidationError[] } {
    return this.validateRequest(schema, req.query, 'query');
  }

  /**
   * Validate request parameters
   */
  protected validateParams<T>(
    req: Request,
    schema: ZodSchema<T>
  ): { success: true; data: T } | { success: false; errors: ValidationError[] } {
    return this.validateRequest(schema, req.params, 'params');
  }

  /**
   * Send successful response with consistent format
   */
  protected sendSuccess<T>(
    res: Response,
    data?: T,
    message = 'Operation successful',
    statusCode = 200
  ): void {
    const response: ApiResponse<T> = {
      success: true,
      data,
      message,
      meta: {
        timestamp: new Date().toISOString(),
        correlationId: res.req.correlationId,
      },
    };
    
    res.status(statusCode).json(response);
  }

  /**
   * Send validation error response
   */
  protected sendValidationError(
    res: Response,
    errors: ValidationError[],
    message = 'Validation failed'
  ): void {
    const response: ApiResponse = {
      success: false,
      message,
      errors,
      meta: {
        timestamp: new Date().toISOString(),
        correlationId: res.req.correlationId,
      },
    };

    res.status(400).json(response);
  }

  /**
   * Send error response with consistent format
   */
  protected sendError(
    res: Response,
    message = 'Internal server error',
    statusCode = 500,
    errors?: ValidationError[]
  ): void {
    const response: ApiResponse = {
      success: false,
      message,
      errors,
      meta: {
        timestamp: new Date().toISOString(),
        correlationId: res.req.correlationId,
      },
    };

    res.status(statusCode).json(response);
  }

  /**
   * Log controller operations with context
   */
  protected logOperation(
    req: Request,
    operation: string,
    data?: Record<string, any>
  ): void {
    logger.info(`Controller operation: ${operation}`, {
      correlationId: req.correlationId,
      userId: req.user?.id,
      method: req.method,
      url: req.originalUrl,
      userAgent: req.get('User-Agent'),
      operation,
      ...data,
    });
  }

  /**
   * Helper method to handle validation and send appropriate response
   */
  protected handleValidation<T>(
    res: Response,
    validationResult: { success: true; data: T } | { success: false; errors: ValidationError[] }
  ): T | null {
    if (!validationResult.success) {
      this.sendValidationError(res, validationResult.errors);
      return null;
    }
    
    return validationResult.data;
  }
}
```

## Usage Example

```typescript
// src/controllers/user.controller.ts
import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { BaseController } from './base.controller';

const CreateUserSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  email: z.string().email('Invalid email format'),
  age: z.number().min(18, 'Must be at least 18 years old').optional(),
});

export class UserController extends BaseController {
  async createUser(req: Request, res: Response, next: NextFunction): Promise<void> {
    await this.executeAsync(req, res, next, async () => {
      // Validate request body
      const validation = this.validateBody(req, CreateUserSchema);
      const userData = this.handleValidation(res, validation);
      
      if (!userData) return; // Validation failed, response already sent
      
      // Business logic here
      const user = await this.userService.create(userData);
      
      return user;
    });
  }
}
```

The implementation follows Express.js best practices for middleware error handling and leverages Zod's `safeParse` method for robust validation without throwing exceptions.

### User Controller Example
```typescript
// src/controllers/user.controller.ts
import { Request, Response, NextFunction } from 'express';
import { BaseController } from './base.controller';
import { UserService } from '@/services/user.service';
import { 
  CreateUserSchema, 
  UpdateUserSchema, 
  GetUsersQuerySchema 
} from '@/types/user.types';

export class UserController extends BaseController {
  constructor(private userService: UserService) {
    super();
  }

  // Use arrow functions to maintain proper 'this' binding
  public createUser = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    this.logOperation(req, 'createUser');
    
    // Added try-catch for better error handling
    try {
      await this.executeAsync(req, res, next, async () => {
        const userData = this.validateRequest(CreateUserSchema, req.body);
        const user = await this.userService.createUser(userData);
        return user;
      });
    } catch (error) {
      // Pass error to Express error handler
      next(error);
    }
  };

  public getUsers = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    this.logOperation(req, 'getUsers');
    
    try {
      await this.executeAsync(req, res, next, async () => {
        const query = this.validateRequest(GetUsersQuerySchema, req.query);
        const result = await this.userService.getUsers(query);
        return result;
      });
    } catch (error) {
      next(error);
    }
  };

  public getUserById = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    this.logOperation(req, 'getUserById', { userId: req.params.id });
    
    try {
      await this.executeAsync(req, res, next, async () => {
        const { id } = req.params;
        // Add validation for ID parameter
        if (!id) {
          throw new Error('User ID is required');
        }
        const user = await this.userService.getUserById(id);
        return user;
      });
    } catch (error) {
      next(error);
    }
  };

  public updateUser = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    this.logOperation(req, 'updateUser', { userId: req.params.id });
    
    try {
      await this.executeAsync(req, res, next, async () => {
        const { id } = req.params;
        // Add validation for ID parameter
        if (!id) {
          throw new Error('User ID is required');
        }
        const updateData = this.validateRequest(UpdateUserSchema, req.body);
        const user = await this.userService.updateUser(id, updateData);
        return user;
      });
    } catch (error) {
      next(error);
    }
  };

  public deleteUser = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    this.logOperation(req, 'deleteUser', { userId: req.params.id });
    
    try {
      await this.executeAsync(req, res, next, async () => {
        const { id } = req.params;
        // Add validation for ID parameter
        if (!id) {
          throw new Error('User ID is required');
        }
        await this.userService.deleteUser(id);
        return { message: 'User deleted successfully' };
      });
    } catch (error) {
      next(error);
    }
  };
}
```

## Service Layer Pattern

### Base Service Class
```typescript
// src/services/base.service.ts
import { logger } from '@/utils/logger';

export abstract class BaseService {
  protected readonly serviceName: string;

  constructor() {
    // Automatically derive service name from class constructor
    this.serviceName = this.constructor.name;
  }

  /**
   * Log a successful operation with structured metadata
   * @param operation - The operation being performed
   * @param data - Additional structured data to include
   * @param correlationId - Optional correlation ID for request tracing
   */
  protected logOperation(
    operation: string,
    data?: Record<string, any>,
    correlationId?: string
  ): void {
    logger.info(`Service operation: ${operation}`, {
      correlationId,
      service: this.serviceName,
      operation,
      timestamp: new Date().toISOString(),
      ...data,
    });
  }

  /**
   * Log an error with structured metadata and stack trace
   * @param operation - The operation that failed
   * @param error - The error that occurred
   * @param data - Additional context data
   * @param correlationId - Optional correlation ID for request tracing
   */
  protected logError(
    operation: string,
    error: Error,
    data?: Record<string, any>,
    correlationId?: string
  ): void {
    logger.error(`Service error: ${operation}`, {
      correlationId,
      service: this.serviceName,
      operation,
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack,
        // Include cause if available (Node.js 16.9.0+)
        ...(error.cause && { cause: error.cause }),
      },
      timestamp: new Date().toISOString(),
      ...data,
    });
  }

  /**
   * Log performance metrics for operations
   * @param operation - The operation being measured
   * @param duration - Duration in milliseconds
   * @param data - Additional performance context
   * @param correlationId - Optional correlation ID for request tracing
   */
  protected logPerformance(
    operation: string,
    duration: number,
    data?: Record<string, any>,
    correlationId?: string
  ): void {
    logger.info(`Service performance: ${operation}`, {
      correlationId,
      service: this.serviceName,
      operation,
      performance: {
        duration,
        unit: 'ms',
      },
      timestamp: new Date().toISOString(),
      ...data,
    });
  }

  /**
   * Log debug information for development and troubleshooting
   * @param operation - The operation context
   * @param data - Debug data to log
   * @param correlationId - Optional correlation ID for request tracing
   */
  protected logDebug(
    operation: string,
    data?: Record<string, any>,
    correlationId?: string
  ): void {
    logger.debug(`Service debug: ${operation}`, {
      correlationId,
      service: this.serviceName,
      operation,
      timestamp: new Date().toISOString(),
      ...data,
    });
  }

  /**
   * Log a warning for non-critical issues
   * @param operation - The operation context
   * @param message - Warning message
   * @param data - Additional context data
   * @param correlationId - Optional correlation ID for request tracing
   */
  protected logWarning(
    operation: string,
    message: string,
    data?: Record<string, any>,
    correlationId?: string
  ): void {
    logger.warn(`Service warning: ${operation} - ${message}`, {
      correlationId,
      service: this.serviceName,
      operation,
      warning: message,
      timestamp: new Date().toISOString(),
      ...data,
    });
  }
}
```

### User Service Implementation
```typescript
// src/services/user.service.ts
import bcrypt from 'bcrypt'; // ✅ Correct import - the actual bcrypt package, not bcryptjs
import { BaseService } from './base.service';
import { UserRepository } from '@/repositories/user.repository';
import { EmailService } from './email.service';
import { 
  CreateUserData, 
  UpdateUserData, 
  UserResponse,
  GetUsersQuery,
  PaginatedUsersResponse 
} from '@/types/user.types';
import { 
  ConflictError, 
  NotFoundError, 
  ValidationError 
} from '@/utils/errors';

export class UserService extends BaseService {
  private readonly SALT_ROUNDS = 12; // ✅ Make salt rounds a constant

  constructor(
    private userRepository: UserRepository,
    private emailService: EmailService
  ) {
    super();
  }

  public async createUser(
    userData: CreateUserData,
    correlationId?: string
  ): Promise<UserResponse> {
    this.logOperation('createUser', { email: userData.email }, correlationId);

    try {
      // Check if user already exists
      const existingUser = await this.userRepository.findByEmail(userData.email);
      if (existingUser) {
        throw new ConflictError('User with this email already exists');
      }

      // ✅ Hash password using one-step method (more efficient)
      const passwordHash = await bcrypt.hash(userData.password, this.SALT_ROUNDS);

      // Create user
      const user = await this.userRepository.create({
        ...userData,
        passwordHash,
        password: undefined, // ✅ Explicitly remove password from create payload
      });

      // Send welcome email (async)
      this.emailService.sendWelcomeEmail(user.email, user.firstName)
        .catch(error => {
          this.logError('sendWelcomeEmail', error, { userId: user.id }, correlationId);
        });

      return this.toUserResponse(user);
    } catch (error) {
      this.logError('createUser', error as Error, { email: userData.email }, correlationId);
      throw error;
    }
  }

  public async getUsers(
    query: GetUsersQuery,
    correlationId?: string
  ): Promise<PaginatedUsersResponse> {
    this.logOperation('getUsers', query, correlationId);

    try {
      const { page = 1, limit = 10, search, role } = query;
      
      // ✅ Add input validation
      if (page < 1 || limit < 1 || limit > 100) {
        throw new ValidationError('Invalid pagination parameters');
      }
      
      const offset = (page - 1) * limit;

      const { users, total } = await this.userRepository.findMany({
        offset,
        limit,
        search,
        role,
      });

      return {
        users: users.map(user => this.toUserResponse(user)),
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit),
          hasNext: page < Math.ceil(total / limit),
          hasPrev: page > 1,
        },
      };
    } catch (error) {
      this.logError('getUsers', error as Error, query, correlationId);
      throw error;
    }
  }

  public async getUserById(
    id: string,
    correlationId?: string
  ): Promise<UserResponse> {
    this.logOperation('getUserById', { userId: id }, correlationId);

    try {
      // ✅ Add basic ID validation
      if (!id || typeof id !== 'string') {
        throw new ValidationError('Invalid user ID');
      }

      const user = await this.userRepository.findById(id);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      return this.toUserResponse(user);
    } catch (error) {
      this.logError('getUserById', error as Error, { userId: id }, correlationId);
      throw error;
    }
  }

  public async updateUser(
    id: string,
    updateData: UpdateUserData,
    correlationId?: string
  ): Promise<UserResponse> {
    this.logOperation('updateUser', { userId: id }, correlationId);

    try {
      // ✅ Add basic ID validation
      if (!id || typeof id !== 'string') {
        throw new ValidationError('Invalid user ID');
      }

      const existingUser = await this.userRepository.findById(id);
      if (!existingUser) {
        throw new NotFoundError('User not found');
      }

      // Check email uniqueness if email is being updated
      if (updateData.email && updateData.email !== existingUser.email) {
        const emailExists = await this.userRepository.findByEmail(updateData.email);
        if (emailExists) {
          throw new ConflictError('Email is already in use');
        }
      }

      // ✅ Improved password handling
      let updatePayload: any = { ...updateData };
      if (updateData.password) {
        // Use one-step hash method
        updatePayload.passwordHash = await bcrypt.hash(updateData.password, this.SALT_ROUNDS);
        delete updatePayload.password; // Remove password from payload
      }

      const updatedUser = await this.userRepository.update(id, updatePayload);
      return this.toUserResponse(updatedUser);
    } catch (error) {
      this.logError('updateUser', error as Error, { userId: id }, correlationId);
      throw error;
    }
  }

  public async deleteUser(
    id: string,
    correlationId?: string
  ): Promise<void> {
    this.logOperation('deleteUser', { userId: id }, correlationId);

    try {
      // ✅ Add basic ID validation
      if (!id || typeof id !== 'string') {
        throw new ValidationError('Invalid user ID');
      }

      const user = await this.userRepository.findById(id);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      await this.userRepository.delete(id);
    } catch (error) {
      this.logError('deleteUser', error as Error, { userId: id }, correlationId);
      throw error;
    }
  }

  // ✅ Add password verification method (commonly needed)
  public async verifyPassword(
    plainPassword: string,
    hashedPassword: string
  ): Promise<boolean> {
    try {
      return await bcrypt.compare(plainPassword, hashedPassword);
    } catch (error) {
      this.logError('verifyPassword', error as Error, {});
      return false;
    }
  }

  private toUserResponse(user: any): UserResponse {
    return {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
      avatar: user.avatar,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt.toISOString(),
      updatedAt: user.updatedAt.toISOString(),
    };
  }
}
```

## Repository Pattern

### Base Repository Class
```typescript
// src/repositories/base.repository.ts
import { PrismaClient, Prisma } from '@prisma/client';
import { logger } from '@/utils/logger';

// Enhanced error types for better error handling
export class RepositoryError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly operation: string,
    public readonly originalError?: Error
  ) {
    super(message);
    this.name = 'RepositoryError';
  }
}

// Transaction context type for transaction support
export type TransactionContext = Omit<PrismaClient, '$connect' | '$disconnect' | '$on' | '$transaction' | '$use'>;

export abstract class BaseRepository<TModel extends string = string> {
  constructor(
    protected readonly prisma: PrismaClient,
    protected readonly modelName: TModel
  ) {}

  /**
   * Enhanced logging with performance metrics and correlation IDs
   */
  protected logQuery<TData = unknown>(
    operation: string,
    data?: TData,
    correlationId?: string,
    startTime?: number
  ): void {
    const duration = startTime ? Date.now() - startTime : undefined;
    
    logger.debug(`Database operation: ${operation}`, {
      repository: this.constructor.name,
      model: this.modelName,
      operation,
      correlationId,
      duration: duration ? `${duration}ms` : undefined,
      data: this.sanitizeLogData(data),
    });
  }

  /**
   * Enhanced error handling with Prisma-specific error types
   */
  protected handleError(
    operation: string,
    error: unknown,
    correlationId?: string,
    data?: Record<string, unknown>
  ): never {
    // Handle Prisma-specific errors
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      this.logPrismaError(operation, error, correlationId, data);
      throw new RepositoryError(
        this.mapPrismaErrorMessage(error),
        error.code,
        operation,
        error
      );
    }

    if (error instanceof Prisma.PrismaClientUnknownRequestError) {
      this.logPrismaError(operation, error, correlationId, data);
      throw new RepositoryError(
        'Unknown database error occurred',
        'UNKNOWN_ERROR',
        operation,
        error
      );
    }

    if (error instanceof Prisma.PrismaClientValidationError) {
      this.logPrismaError(operation, error, correlationId, data);
      throw new RepositoryError(
        'Database validation error',
        'VALIDATION_ERROR',
        operation,
        error
      );
    }

    // Handle generic errors
    const message = error instanceof Error ? error.message : 'Unknown error';
    logger.error(`Database error: ${operation}`, {
      repository: this.constructor.name,
      model: this.modelName,
      operation,
      correlationId,
      error: message,
      stack: error instanceof Error ? error.stack : undefined,
      data: this.sanitizeLogData(data),
    });

    throw new RepositoryError(
      'An unexpected database error occurred',
      'UNEXPECTED_ERROR',
      operation,
      error instanceof Error ? error : new Error(String(error))
    );
  }

  /**
   * Execute operation with comprehensive logging and error handling
   */
  protected async executeOperation<TResult>(
    operation: string,
    fn: () => Promise<TResult>,
    data?: Record<string, unknown>,
    correlationId?: string
  ): Promise<TResult> {
    const startTime = Date.now();
    
    try {
      this.logQuery(operation, data, correlationId, startTime);
      const result = await fn();
      this.logQuery(`${operation}:success`, { resultCount: Array.isArray(result) ? result.length : 1 }, correlationId, startTime);
      return result;
    } catch (error) {
      this.handleError(operation, error, correlationId, data);
    }
  }

  /**
   * Execute operation within transaction context
   */
  protected async executeInTransaction<TResult>(
    operation: string,
    fn: (tx: TransactionContext) => Promise<TResult>,
    data?: Record<string, unknown>,
    correlationId?: string
  ): Promise<TResult> {
    return this.executeOperation(
      `${operation}:transaction`,
      () => this.prisma.$transaction(fn),
      data,
      correlationId
    );
  }

  /**
   * Log Prisma-specific errors with enhanced context
   */
  private logPrismaError(
    operation: string,
    error: Prisma.PrismaClientKnownRequestError | Prisma.PrismaClientUnknownRequestError | Prisma.PrismaClientValidationError,
    correlationId?: string,
    data?: Record<string, unknown>
  ): void {
    logger.error(`Prisma error: ${operation}`, {
      repository: this.constructor.name,
      model: this.modelName,
      operation,
      correlationId,
      errorCode: 'code' in error ? error.code : 'UNKNOWN',
      errorMessage: error.message,
      meta: 'meta' in error ? error.meta : undefined,
      data: this.sanitizeLogData(data),
    });
  }

  /**
   * Map Prisma error codes to user-friendly messages
   */
  private mapPrismaErrorMessage(error: Prisma.PrismaClientKnownRequestError): string {
    switch (error.code) {
      case 'P2002':
        return 'A record with this information already exists';
      case 'P2025':
        return 'Record not found';
      case 'P2003':
        return 'Foreign key constraint failed';
      case 'P2014':
        return 'Invalid data provided';
      default:
        return `Database operation failed: ${error.message}`;
    }
  }

  /**
   * Sanitize sensitive data from logs
   */
  private sanitizeLogData(data: unknown): unknown {
    if (!data || typeof data !== 'object') return data;

    const sensitiveFields = ['password', 'token', 'secret', 'key', 'authorization'];
    const sanitized = { ...data as Record<string, unknown> };

    for (const field of sensitiveFields) {
      if (field in sanitized) {
        sanitized[field] = '[REDACTED]';
      }
    }

    return sanitized;
  }
}
```

### User Repository Implementation
```typescript
// src/repositories/user.repository.ts
import { PrismaClient, User, Prisma } from '@prisma/client';
import { BaseRepository } from './base.repository';

interface FindManyOptions {
  offset: number;
  limit: number;
  search?: string;
  role?: string;
}

interface FindManyResult {
  users: User[];
  total: number;
}

export class UserRepository extends BaseRepository {
  constructor(prisma: PrismaClient) {
    super(prisma);
  }

  public async create(userData: Prisma.UserCreateInput): Promise<User> {
    this.logQuery('create', 'User', { email: userData.email });
    try {
      return await this.prisma.user.create({
        data: userData,
      });
    } catch (error) {
      // Fix: Re-throw the error after logging instead of returning undefined
      this.handleError('create', error as Error, { email: userData.email });
      throw error; // Ensure the method always returns Promise<User> or throws
    }
  }

  public async findById(id: string): Promise<User | null> {
    this.logQuery('findById', 'User', { id });
    try {
      return await this.prisma.user.findUnique({
        where: { id },
      });
    } catch (error) {
      this.handleError('findById', error as Error, { id });
      throw error; // Fix: Re-throw to maintain return type consistency
    }
  }

  public async findByEmail(email: string): Promise<User | null> {
    this.logQuery('findByEmail', 'User', { email });
    try {
      return await this.prisma.user.findUnique({
        where: { email },
      });
    } catch (error) {
      this.handleError('findByEmail', error as Error, { email });
      throw error; // Fix: Re-throw the error
    }
  }

  public async findMany(options: FindManyOptions): Promise<FindManyResult> {
    this.logQuery('findMany', 'User', options);
    try {
      const { offset, limit, search, role } = options;
      const where: Prisma.UserWhereInput = {};
      
      if (search) {
        where.OR = [
          { firstName: { contains: search, mode: 'insensitive' } },
          { lastName: { contains: search, mode: 'insensitive' } },
          { email: { contains: search, mode: 'insensitive' } },
        ];
      }
      
      if (role) {
        where.role = role;
      }

      const [users, total] = await Promise.all([
        this.prisma.user.findMany({
          where,
          skip: offset,
          take: limit,
          orderBy: { createdAt: 'desc' },
        }),
        this.prisma.user.count({ where }),
      ]);

      return { users, total };
    } catch (error) {
      this.handleError('findMany', error as Error, options);
      throw error; // Fix: Re-throw the error
    }
  }

  public async update(
    id: string,
    updateData: Prisma.UserUpdateInput
  ): Promise<User> {
    this.logQuery('update', 'User', { id });
    try {
      return await this.prisma.user.update({
        where: { id },
        data: updateData,
      });
    } catch (error) {
      this.handleError('update', error as Error, { id });
      throw error; // Fix: Re-throw the error
    }
  }

  public async delete(id: string): Promise<void> {
    this.logQuery('delete', 'User', { id });
    try {
      await this.prisma.user.delete({
        where: { id },
      });
      // Fix: Explicit return for void methods is optional but clear
    } catch (error) {
      this.handleError('delete', error as Error, { id });
      throw error; // Fix: Re-throw the error
    }
  }
}
```
## Additional Improvements to Consider
```typescript
// Optional: Add specific Prisma error handling
import { Prisma } from '@prisma/client';

public async create(userData: Prisma.UserCreateInput): Promise<User> {
  this.logQuery('create', 'User', { email: userData.email });
  try {
    return await this.prisma.user.create({
      data: userData,
    });
  } catch (error) {
    // Handle specific Prisma errors
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      if (error.code === 'P2002') {
        // Unique constraint violation
        this.handleError('create', new Error('User with this email already exists'), { email: userData.email });
        throw new Error('User with this email already exists');
      }
    }
    this.handleError('create', error as Error, { email: userData.email });
    throw error;
  }
}
```

## Type Definitions

### API Types
```typescript
// src/types/api.types.ts

/**
 * Standard API response wrapper with generic data type
 * @template T - The type of the data payload
 */
export interface ApiResponse<T = any> {
  /** Indicates if the operation was successful */
  success: boolean;
  /** The response payload */
  data: T;
  /** Optional human-readable message */
  message?: string;
  /** Field-specific validation errors */
  errors?: Record<string, string[]>;
  /** Additional metadata about the response */
  meta?: {
    /** ISO timestamp of the response */
    timestamp: string;
    /** API version that generated this response */
    version?: string;
    /** Request ID for tracing */
    requestId?: string;
  };
}

/**
 * Query parameters for pagination
 */
export interface PaginationQuery {
  /** Page number (1-based indexing) */
  page?: number;
  /** Number of items per page */
  limit?: number;
  /** Optional sorting field */
  sortBy?: string;
  /** Sort direction */
  sortOrder?: 'asc' | 'desc';
}

/**
 * Metadata about pagination state
 */
export interface PaginationMeta {
  /** Current page number (1-based) */
  page: number;
  /** Items per page */
  limit: number;
  /** Total number of items across all pages */
  total: number;
  /** Total number of pages */
  totalPages: number;
  /** Whether there is a next page available */
  hasNext: boolean;
  /** Whether there is a previous page available */
  hasPrev: boolean;
}

/**
 * Paginated response wrapper
 * @template T - The type of items in the data array
 */
export interface PaginatedResponse<T> {
  /** Array of items for the current page */
  data: T[];
  /** Pagination metadata */
  pagination: PaginationMeta;
}

/**
 * Error response type for failed API calls
 */
export interface ApiErrorResponse {
  success: false;
  message: string;
  errors?: Record<string, string[]>;
  code?: string;
  meta?: {
    timestamp: string;
    requestId?: string;
  };
}

/**
 * Union type for all possible API responses
 * @template T - The type of successful response data
 */
export type ApiResult<T> = ApiResponse<T> | ApiErrorResponse;
```

### User Types with Validation
```typescript
// src/types/user.types.ts
import { z } from 'zod';

// Validation schemas
export const CreateUserSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/, // Fixed: Added + at the end
      'Password must contain uppercase, lowercase, number and special character'
    ),
  firstName: z.string().min(1, 'First name is required').max(50),
  lastName: z.string().min(1, 'Last name is required').max(50),
  role: z.enum(['admin', 'user', 'moderator']).default('user'),
});

export const UpdateUserSchema = z.object({
  email: z.string().email('Invalid email format').optional(),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/, // Fixed: Added + at the end
      'Password must contain uppercase, lowercase, number and special character'
    )
    .optional(),
  firstName: z.string().min(1).max(50).optional(),
  lastName: z.string().min(1).max(50).optional(),
  avatar: z.string().url('Invalid avatar URL').optional(),
});

export const GetUsersQuerySchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(10),
  search: z.string().optional(),
  role: z.enum(['admin', 'user', 'moderator']).optional(),
});

// Type inference from schemas
export type CreateUserData = z.infer<typeof CreateUserSchema>;
export type UpdateUserData = z.infer<typeof UpdateUserSchema>;
export type GetUsersQuery = z.infer<typeof GetUsersQuerySchema>;

// Response types
export interface UserResponse {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  avatar?: string;
  isEmailVerified: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface PaginatedUsersResponse {
  users: UserResponse[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}
```

## Middleware Implementation

### Authentication Middleware
```typescript
// src/middleware/auth.middleware.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '@/config';
import { UserRepository } from '@/repositories/user.repository';
import { UnauthorizedError, ForbiddenError } from '@/utils/errors';

interface JwtPayload {
  userId: string;
  email: string;
  role: string;
  iat: number;
  exp: number;
}

// Extend Express Request interface to include user property
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
        role: string;
      };
    }
  }
}

export class AuthMiddleware {
  constructor(private userRepository: UserRepository) {}

  public authenticate = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new UnauthorizedError('Missing or invalid authorization header');
      }
      
      const token = authHeader.substring(7); // Extract token after "Bearer "
      
      // Add null check for empty token
      if (!token) {
        throw new UnauthorizedError('Token is required');
      }
      
      const decoded = jwt.verify(token, config.jwt.publicKey, {
        algorithms: ['RS256'], // Specify allowed algorithms to prevent algorithm confusion attacks
      }) as JwtPayload;
      
      // Verify user still exists and is active
      const user = await this.userRepository.findById(decoded.userId);
      if (!user) {
        throw new UnauthorizedError('User not found');
      }
      
      // Additional check: verify user is still active/enabled
      if (user.status === 'disabled' || user.status === 'suspended') {
        throw new UnauthorizedError('User account is disabled');
      }
      
      // Attach user to request
      req.user = {
        id: user.id,
        email: user.email,
        role: user.role,
      };
      
      next();
    } catch (error) {
      // Handle specific JWT errors for better error messages
      if (error instanceof jwt.TokenExpiredError) {
        next(new UnauthorizedError('Token has expired'));
      } else if (error instanceof jwt.JsonWebTokenError) {
        next(new UnauthorizedError('Invalid token'));
      } else if (error instanceof jwt.NotBeforeError) {
        next(new UnauthorizedError('Token not yet valid'));
      } else {
        next(error);
      }
    }
  };

  public authorize = (allowedRoles: string[]) => {
    return (req: Request, res: Response, next: NextFunction): void => {
      if (!req.user) {
        return next(new UnauthorizedError('Authentication required'));
      }
      
      if (!allowedRoles.includes(req.user.role)) {
        return next(new ForbiddenError('Insufficient permissions'));
      }
      
      next();
    };
  };
}
```

### Error Handling Middleware
```typescript
// src/middleware/error.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { Prisma } from '@prisma/client';
import { logger } from '@/utils/logger';

export class AppError extends Error {
  public readonly statusCode: number;
  public readonly isOperational: boolean;

  constructor(message: string, statusCode: number, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    Error.captureStackTrace(this, this.constructor);
  }
}

export class ValidationError extends AppError {
  constructor(message: string, public readonly details?: Record<string, string[]>) {
    super(message, 400);
  }
}

export class NotFoundError extends AppError {
  constructor(message = 'Resource not found') {
    super(message, 404);
  }
}

export class ConflictError extends AppError {
  constructor(message = 'Resource conflict') {
    super(message, 409);
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = 'Unauthorized') {
    super(message, 401);
  }
}

export class ForbiddenError extends AppError {
  constructor(message = 'Forbidden') {
    super(message, 403);
  }
}

export function errorHandler(
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  logger.error('Error caught by global handler', {
    error: error.message,
    stack: error.stack,
    correlationId: req.correlationId,
    url: req.url,
    method: req.method,
    userId: req.user?.id,
  });

  // Zod validation errors
  if (error instanceof ZodError) {
    const details: Record<string, string[]> = {};
    error.errors.forEach((err) => {
      const path = err.path.join('.');
      if (!details[path]) {
        details[path] = [];
      }
      details[path].push(err.message);
    });

    return res.status(400).json({
      success: false,
      error: 'VALIDATION_ERROR',
      message: 'Validation failed',
      details,
      meta: {
        timestamp: new Date().toISOString(),
      },
    });
  }

  // Prisma errors
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    // P2002: Unique constraint violation
    if (error.code === 'P2002') {
      return res.status(409).json({
        success: false,
        error: 'CONFLICT',
        message: 'Resource already exists',
        meta: {
          timestamp: new Date().toISOString(),
          target: error.meta?.target, // Added: Include constraint details
        },
      });
    }

    // P2025: Record not found (used by findUniqueOrThrow, findFirstOrThrow)
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        error: 'NOT_FOUND',
        message: 'Resource not found',
        meta: {
          timestamp: new Date().toISOString(),
        },
      });
    }

    // P2003: Foreign key constraint violation
    if (error.code === 'P2003') {
      return res.status(400).json({
        success: false,
        error: 'FOREIGN_KEY_CONSTRAINT',
        message: 'Invalid reference to related resource',
        meta: {
          timestamp: new Date().toISOString(),
          field: error.meta?.field_name,
        },
      });
    }

    // P2011: Null constraint violation
    if (error.code === 'P2011') {
      return res.status(400).json({
        success: false,
        error: 'NULL_CONSTRAINT',
        message: 'Required field cannot be null',
        meta: {
          timestamp: new Date().toISOString(),
          constraint: error.meta?.constraint,
        },
      });
    }

    // Generic Prisma known error handler
    return res.status(400).json({
      success: false,
      error: 'DATABASE_ERROR',
      message: 'A database error occurred',
      meta: {
        timestamp: new Date().toISOString(),
        code: error.code,
      },
    });
  }

  // Prisma Client Validation Errors (schema validation issues)
  if (error instanceof Prisma.PrismaClientValidationError) {
    return res.status(400).json({
      success: false,
      error: 'VALIDATION_ERROR',
      message: 'Database validation failed',
      meta: {
        timestamp: new Date().toISOString(),
      },
    });
  }

  // Application errors
  if (error instanceof AppError) {
    const response: any = {
      success: false,
      error: error.constructor.name.replace('Error', '').toUpperCase(),
      message: error.message,
      meta: {
        timestamp: new Date().toISOString(),
      },
    };

    if (error instanceof ValidationError && error.details) {
      response.details = error.details;
    }

    return res.status(error.statusCode).json(response);
  }

  // Default error response
  const statusCode = 500; // Fixed: Remove redundant conditional
  const message = process.env.NODE_ENV === 'production' 
    ? 'Internal server error' 
    : error.message;

  res.status(statusCode).json({
    success: false,
    error: 'INTERNAL_SERVER_ERROR',
    message,
    ...(process.env.NODE_ENV !== 'production' && { stack: error.stack }),
    meta: {
      timestamp: new Date().toISOString(),
    },
  });
}
```

## Testing Strategy

### Unit Testing Setup
```typescript
// tests/unit/services/user.service.test.ts
import { UserService } from '@/services/user.service';
import { UserRepository } from '@/repositories/user.repository';
import { EmailService } from '@/services/email.service';
import { ConflictError, NotFoundError } from '@/utils/errors';

// Properly typed mock dependencies using jest.Mocked<T>
const mockUserRepository = {
  findByEmail: jest.fn(),
  create: jest.fn(),
  findById: jest.fn(),
  findMany: jest.fn(),
  update: jest.fn(),
  delete: jest.fn(),
} as jest.Mocked<UserRepository>;

const mockEmailService = {
  sendWelcomeEmail: jest.fn(),
} as jest.Mocked<EmailService>;

describe('UserService', () => {
  let userService: UserService;

  beforeEach(() => {
    userService = new UserService(mockUserRepository, mockEmailService);
    jest.clearAllMocks(); // Reset all mocks before each test
  });

  describe('createUser', () => {
    const userData = {
      email: 'test@example.com',
      password: 'Password123!',
      firstName: 'John',
      lastName: 'Doe',
      role: 'user' as const,
    };

    it('should create a user successfully', async () => {
      const createdUser = {
        id: '123',
        email: userData.email,
        firstName: userData.firstName,
        lastName: userData.lastName,
        role: userData.role,
        avatar: null,
        isEmailVerified: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      // Mock return values for dependencies
      mockUserRepository.findByEmail.mockResolvedValue(null);
      mockUserRepository.create.mockResolvedValue(createdUser);
      mockEmailService.sendWelcomeEmail.mockResolvedValue(undefined);

      const result = await userService.createUser(userData);

      // Verify method calls with proper arguments
      expect(mockUserRepository.findByEmail).toHaveBeenCalledWith(userData.email);
      expect(mockUserRepository.create).toHaveBeenCalledWith({
        ...userData,
        passwordHash: expect.any(String), // Assuming password is hashed
      });
      expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalledWith(userData.email); // Added missing assertion
      expect(result.email).toBe(userData.email);
      expect(result.id).toBe('123');
    });

    it('should throw ConflictError if user already exists', async () => {
      const existingUser = { id: '456', email: userData.email };
      mockUserRepository.findByEmail.mockResolvedValue(existingUser as any);

      await expect(userService.createUser(userData))
        .rejects
        .toThrow(ConflictError);

      expect(mockUserRepository.create).not.toHaveBeenCalled();
      expect(mockEmailService.sendWelcomeEmail).not.toHaveBeenCalled(); // Added missing assertion
    });
  });

  describe('getUserById', () => {
    it('should return user when found', async () => {
      const user = {
        id: '123',
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        role: 'user',
        avatar: null,
        isEmailVerified: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockUserRepository.findById.mockResolvedValue(user);

      const result = await userService.getUserById('123');

      expect(mockUserRepository.findById).toHaveBeenCalledWith('123');
      expect(result.id).toBe('123');
      expect(result.email).toBe('test@example.com');
    });

    it('should throw NotFoundError when user not found', async () => {
      mockUserRepository.findById.mockResolvedValue(null);

      await expect(userService.getUserById('123'))
        .rejects
        .toThrow(NotFoundError);
    });
  });
});
```

### Integration Testing
```typescript
// tests/integration/user.routes.test.ts
import request from 'supertest';
import { createApp } from '@/app';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const app = createApp();

describe('User Routes', () => {
  beforeEach(async () => {
    // Clean up database before each test
    await prisma.user.deleteMany();
  });

  afterAll(async () => {
    // Clean up database after all tests and disconnect
    await prisma.user.deleteMany();
    await prisma.$disconnect();
  });

  describe('POST /api/v1/users', () => {
    const validUserData = {
      email: 'test@example.com',
      password: 'Password123!',
      firstName: 'John',
      lastName: 'Doe',
    };

    it('should create a user with valid data', async () => {
      const response = await request(app)
        .post('/api/v1/users')
        .send(validUserData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.email).toBe(validUserData.email);
      expect(response.body.data.firstName).toBe(validUserData.firstName);
      expect(response.body.data).not.toHaveProperty('password');
    });

    it('should return 400 for invalid email', async () => {
      const response = await request(app)
        .post('/api/v1/users')
        .send({
          ...validUserData,
          email: 'invalid-email',
        })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('VALIDATION_ERROR');
    });

    it('should return 409 for duplicate email', async () => {
      // Create first user
      await request(app)
        .post('/api/v1/users')
        .send(validUserData)
        .expect(201);

      // Try to create user with same email
      const response = await request(app)
        .post('/api/v1/users')
        .send(validUserData)
        .expect(409);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('CONFLICT');
    });
  });

  describe('GET /api/v1/users', () => {
    it('should return paginated users', async () => {
      // Create test users using Promise.all for better performance
      await Promise.all([
        request(app).post('/api/v1/users').send({
          email: 'user1@example.com',
          password: 'Password123!',
          firstName: 'User',
          lastName: 'One',
        }),
        request(app).post('/api/v1/users').send({
          email: 'user2@example.com',
          password: 'Password123!',
          firstName: 'User',
          lastName: 'Two',
        }),
      ]);

      const response = await request(app)
        .get('/api/v1/users?page=1&limit=10')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.users).toHaveLength(2);
      expect(response.body.data.pagination.total).toBe(2);
    });
  });
});
```
## Additional Recommendations:
Consider Using Test Database: Ensure you're using a separate test database to avoid interfering with development data.
Environment Variables: Consider using different database URLs for testing:
```typescript
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.TEST_DATABASE_URL || process.env.DATABASE_URL
    }
  }
});
```

## Database Configuration

### Prisma Schema Example
```prisma
// prisma/schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id              String    @id @default(cuid())
  email           String    @unique
  passwordHash    String
  firstName       String
  lastName        String
  role            Role      @default(USER)
  avatar          String?
  isEmailVerified Boolean   @default(false)
  emailVerifiedAt DateTime?
  createdAt       DateTime  @default(now())
  updatedAt       DateTime  @updatedAt
  deletedAt       DateTime?
  
  // Relations
  sessions Session[]
  posts    Post[]
  
  @@map("users")
  @@index([email])
  @@index([createdAt])
  @@index([deletedAt])
}

model Session {
  id        String   @id @default(cuid())
  userId    String
  token     String   @unique
  expiresAt DateTime
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  
  // Relations
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)
  
  @@map("sessions")
  @@index([userId])
  @@index([token])
  @@index([expiresAt])
}

model Post {
  id        String   @id @default(cuid())
  title     String
  content   String
  published Boolean  @default(false)
  authorId  String   // Changed: Fixed type mismatch
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  
  // Relations
  author User @relation(fields: [authorId], references: [id], onDelete: Cascade)
  
  @@map("posts")
  @@index([authorId])
  @@index([published])
  @@index([createdAt])
}

enum Role {
  ADMIN
  USER
  MODERATOR
}
```

### Database Configuration
```typescript
// src/config/database.ts
import { PrismaClient } from '@prisma/client';
import { logger } from '@/utils/logger';

// Global type augmentation for better TypeScript support
const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

export const prisma = globalForPrisma.prisma ?? new PrismaClient({
  log: [
    { emit: 'event', level: 'query' },
    { emit: 'event', level: 'error' },
    { emit: 'event', level: 'info' },
    { emit: 'event', level: 'warn' },
  ],
});

// Log database queries in development
if (process.env.NODE_ENV === 'development') {
  prisma.$on('query', (e) => {
    logger.debug('Database Query', {
      query: e.query,
      params: e.params,
      duration: `${e.duration}ms`,
      timestamp: e.timestamp, // Added timestamp logging
    });
  });
}

// Enhanced error logging with more context
prisma.$on('error', (e) => {
  logger.error('Database Error', {
    target: e.target,
    message: e.message,
    timestamp: e.timestamp, // Added timestamp logging
  });
});

// Log info and warn events for better observability
prisma.$on('info', (e) => {
  logger.info('Database Info', {
    message: e.message,
    target: e.target,
    timestamp: e.timestamp,
  });
});

prisma.$on('warn', (e) => {
  logger.warn('Database Warning', {
    message: e.message,
    target: e.target,
    timestamp: e.timestamp,
  });
});

// Use beforeExit hook for graceful shutdown logging
prisma.$on('beforeExit', async () => {
  logger.info('Database connection shutting down');
  // PrismaClient is still available here for final operations if needed
});

// Only store in global during non-production to prevent multiple instances
if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = prisma;
}

export async function connectDatabase(): Promise<void> {
  try {
    await prisma.$connect();
    logger.info('Database connected successfully');
  } catch (error) {
    logger.error('Failed to connect to database', { error });
    throw error;
  }
}

export async function disconnectDatabase(): Promise<void> {
  try {
    await prisma.$disconnect();
    logger.info('Database disconnected');
  } catch (error) {
    logger.error('Error disconnecting from database', { error });
    // Don't throw in disconnect to avoid masking original errors
  }
}
```

## Security Implementation

### JWT Configuration
```typescript
// src/config/jwt.ts
import fs from 'fs';
import path from 'path';
import jwt from 'jsonwebtoken';
import { config } from './index';

// Define proper interfaces for JWT payloads
interface JWTPayload {
  userId: string;
  email: string;
  role: string;
}

interface RefreshTokenPayload {
  userId: string;
}

interface DecodedToken extends JWTPayload {
  iat: number;
  exp: number;
  iss: string;
  aud: string;
}

class JWTService {
  private privateKey: string;
  private publicKey: string;

  constructor() {
    try {
      if (process.env.NODE_ENV === 'production') {
        // In production, use environment variables
        this.privateKey = process.env.JWT_PRIVATE_KEY?.replace(/\\n/g, '\n') || '';
        this.publicKey = process.env.JWT_PUBLIC_KEY?.replace(/\\n/g, '\n') || '';
        
        // Validate that keys are provided in production
        if (!this.privateKey || !this.publicKey) {
          throw new Error('JWT keys must be provided via environment variables in production');
        }
      } else {
        // In development, use local key files
        const privateKeyPath = path.join(process.cwd(), 'keys', 'private.pem');
        const publicKeyPath = path.join(process.cwd(), 'keys', 'public.pem');
        
        // Check if key files exist before reading
        if (!fs.existsSync(privateKeyPath) || !fs.existsSync(publicKeyPath)) {
          throw new Error(`JWT key files not found. Please ensure ${privateKeyPath} and ${publicKeyPath} exist.`);
        }
        
        this.privateKey = fs.readFileSync(privateKeyPath, 'utf8');
        this.publicKey = fs.readFileSync(publicKeyPath, 'utf8');
      }
      
      // Validate that keys are not empty
      if (!this.privateKey.trim() || !this.publicKey.trim()) {
        throw new Error('JWT keys cannot be empty');
      }
      
    } catch (error) {
      throw new Error(`Failed to initialize JWT service: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  public generateTokens(payload: JWTPayload): { accessToken: string; refreshToken: string } {
    try {
      const accessToken = jwt.sign(payload, this.privateKey, {
        algorithm: 'RS256',
        expiresIn: config.jwt.accessTokenExpiry,
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
      });

      const refreshToken = jwt.sign(
        { userId: payload.userId } as RefreshTokenPayload,
        this.privateKey,
        {
          algorithm: 'RS256',
          expiresIn: config.jwt.refreshTokenExpiry,
          issuer: config.jwt.issuer,
          audience: config.jwt.audience,
        }
      );

      return { accessToken, refreshToken };
    } catch (error) {
      throw new Error(`Failed to generate tokens: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  public verifyToken(token: string): DecodedToken {
    try {
      const decoded = jwt.verify(token, this.publicKey, {
        algorithms: ['RS256'],
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
      }) as DecodedToken;
      
      return decoded;
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        throw new Error(`Invalid token: ${error.message}`);
      } else if (error instanceof jwt.TokenExpiredError) {
        throw new Error('Token has expired');
      } else if (error instanceof jwt.NotBeforeError) {
        throw new Error('Token not active yet');
      } else {
        throw new Error(`Token verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
  }

  public getPublicKey(): string {
    return this.publicKey;
  }

  // Additional helper method to verify refresh tokens specifically
  public verifyRefreshToken(token: string): RefreshTokenPayload & { iat: number; exp: number; iss: string; aud: string } {
    try {
      const decoded = jwt.verify(token, this.publicKey, {
        algorithms: ['RS256'],
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
      }) as RefreshTokenPayload & { iat: number; exp: number; iss: string; aud: string };
      
      return decoded;
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        throw new Error(`Invalid refresh token: ${error.message}`);
      } else if (error instanceof jwt.TokenExpiredError) {
        throw new Error('Refresh token has expired');
      } else if (error instanceof jwt.NotBeforeError) {
        throw new Error('Refresh token not active yet');
      } else {
        throw new Error(`Refresh token verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
  }
}

// Use a factory function instead of direct instantiation to handle initialization errors
let jwtServiceInstance: JWTService | null = null;

export const getJWTService = (): JWTService => {
  if (!jwtServiceInstance) {
    jwtServiceInstance = new JWTService();
  }
  return jwtServiceInstance;
};

// For backward compatibility, but prefer using getJWTService()
export const jwtService = getJWTService();
```

### Rate Limiting Configuration
```typescript
// src/middleware/rate-limit.middleware.ts
import rateLimit from 'express-rate-limit';
import { RedisStore } from 'rate-limit-redis';
import { redis } from '@/config/redis';

// General API rate limiting
export const generalLimiter = rateLimit({
  store: new RedisStore({
    // FIXED: Use sendCommand method instead of call
    sendCommand: (...args: string[]) => redis.sendCommand(args),
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: 'RATE_LIMIT_EXCEEDED',
    message: 'Too many requests, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Strict rate limiting for authentication endpoints
export const authLimiter = rateLimit({
  store: new RedisStore({
    // FIXED: Use sendCommand method instead of call
    sendCommand: (...args: string[]) => redis.sendCommand(args),
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: {
    error: 'AUTH_RATE_LIMIT_EXCEEDED',
    message: 'Too many authentication attempts, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Password reset rate limiting
export const passwordResetLimiter = rateLimit({
  store: new RedisStore({
    // FIXED: Use sendCommand method instead of call
    sendCommand: (...args: string[]) => redis.sendCommand(args),
  }),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 password reset requests per hour
  message: {
    error: 'PASSWORD_RESET_RATE_LIMIT_EXCEEDED',
    message: 'Too many password reset attempts, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});
```

## Environment Configuration

### Configuration Management
```typescript
// src/config/index.ts
import dotenv from 'dotenv';
import { z } from 'zod';

// Load environment variables before parsing
dotenv.config();

// Environment validation schema with error handling improvements
const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(8000),
  
  // Database
  DATABASE_URL: z.string().min(1, 'Database URL is required'),
  
  // Redis
  REDIS_URL: z.string().min(1, 'Redis URL is required'),
  
  // JWT
  JWT_PRIVATE_KEY: z.string().min(1, 'JWT private key is required'),
  JWT_PUBLIC_KEY: z.string().min(1, 'JWT public key is required'),
  JWT_ACCESS_TOKEN_EXPIRY: z.string().default('15m'),
  JWT_REFRESH_TOKEN_EXPIRY: z.string().default('7d'),
  JWT_ISSUER: z.string().default('api.example.com'),
  JWT_AUDIENCE: z.string().default('example.com'),
  
  // CORS
  CORS_ORIGINS: z.string().default('http://localhost:3000'),
  
  // Email
  SMTP_HOST: z.string().min(1, 'SMTP host is required'),
  SMTP_PORT: z.coerce.number().default(587),
  SMTP_USER: z.string().min(1, 'SMTP user is required'),
  SMTP_PASS: z.string().min(1, 'SMTP password is required'),
  
  // Monitoring
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
});

// Validate environment variables with proper error handling
let env: z.infer<typeof envSchema>;

try {
  env = envSchema.parse(process.env);
} catch (error) {
  if (error instanceof z.ZodError) {
    console.error('Environment validation failed:');
    error.issues.forEach((issue) => {
      console.error(`- ${issue.path.join('.')}: ${issue.message}`);
    });
    process.exit(1);
  }
  throw error;
}

export const config = {
  env: env.NODE_ENV,
  port: env.PORT,
  
  database: {
    url: env.DATABASE_URL,
  },
  
  redis: {
    url: env.REDIS_URL,
  },
  
  jwt: {
    // Proper handling of multiline environment variables
    privateKey: env.JWT_PRIVATE_KEY.replace(/\\n/g, '\n'),
    publicKey: env.JWT_PUBLIC_KEY.replace(/\\n/g, '\n'),
    accessTokenExpiry: env.JWT_ACCESS_TOKEN_EXPIRY,
    refreshTokenExpiry: env.JWT_REFRESH_TOKEN_EXPIRY,
    issuer: env.JWT_ISSUER,
    audience: env.JWT_AUDIENCE,
  },
  
  cors: {
    // Better handling of comma-separated values with validation
    origins: env.CORS_ORIGINS.split(',').map(origin => origin.trim()).filter(Boolean),
  },
  
  email: {
    host: env.SMTP_HOST,
    port: env.SMTP_PORT,
    user: env.SMTP_USER,
    pass: env.SMTP_PASS,
  },
  
  logging: {
    level: env.LOG_LEVEL,
  },
} as const;
```

## Deployment Configuration

### Dockerfile
```dockerfile
# syntax=docker/dockerfile:1

# Multi-stage Dockerfile for Node.js application with Prisma
ARG NODE_VERSION=20.18.0

# Base stage for common configuration
FROM node:${NODE_VERSION}-alpine AS base
# Install system dependencies for native modules and database connections
RUN apk add --no-cache \
    libc6-compat \
    openssl \
    ca-certificates
WORKDIR /app

# Dependency installation stage  
FROM base AS deps
# Copy package files for dependency installation
COPY package*.json ./
COPY prisma ./prisma/
# Install dependencies with cache mount for better performance
RUN --mount=type=cache,target=/root/.npm \
    npm ci --only=production && \
    npm cache clean --force

# Build stage for development dependencies and Prisma generation
FROM base AS builder
# Install all dependencies (including dev) with cache mount
RUN --mount=type=cache,target=/root/.npm \
    --mount=type=bind,source=package*.json,target=. \
    --mount=type=bind,source=prisma,target=./prisma \
    npm ci

# Copy source code for build
COPY . .
# Generate Prisma client
RUN npx prisma generate
# Build the application
RUN npm run build

# Production runtime stage
FROM base AS runner
# Create non-root user with specific UID/GID for security
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 --ingroup nodejs nodejs

# Copy built application and dependencies from previous stages
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=deps --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/package.json ./package.json
COPY --from=builder --chown=nodejs:nodejs /app/prisma ./prisma

# Switch to non-root user for security
USER nodejs

# Expose application port
EXPOSE 8000

# Health check with improved implementation
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e " \
        require('http').get('http://localhost:8000/health', (res) => { \
            process.exit(res.statusCode === 200 ? 0 : 1); \
        }).on('error', () => process.exit(1)); \
    "

# Start the application
CMD ["npm", "start"]
```

### Docker Compose for Development
```yaml
# docker-compose.yml
services:  # ← REMOVED deprecated 'version' field
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      - NODE_ENV=development
      - DATABASE_URL=postgresql://postgres:password@postgres:5432/app_db
      - REDIS_URL=redis://redis:6379
    depends_on:
      postgres:
        condition: service_healthy  # ← Added health check dependency
      redis:
        condition: service_started  # ← Added explicit condition
    volumes:
      - .:/app
      - /app/node_modules
    command: npm run dev
    restart: unless-stopped  # ← Added restart policy

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=app_db
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:  # ← Added health check for better dependency management
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
    restart: unless-stopped  # ← Added restart policy

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes  # ← Added persistence
    healthcheck:  # ← Added health check
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped  # ← Added restart policy

volumes:
  postgres_data:
  redis_data:
```

## Additional Best Practices

### Logging Configuration
```typescript
// src/utils/logger.ts
import winston from 'winston';
import { config } from '@/config';

const logFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Define base transports for all environments
const baseTransports: winston.transport[] = [
  new winston.transports.File({
    filename: 'logs/error.log',
    level: 'error',
  }),
  new winston.transports.File({
    filename: 'logs/combined.log',
  }),
];

// Add console transport only for non-production environments
const transports = config.env === 'production' 
  ? baseTransports 
  : [
      ...baseTransports,
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.simple()
        ),
      }),
    ];

export const logger = winston.createLogger({
  level: config.logging.level,
  format: logFormat,
  transports,
});
```

### Health Check Implementation
```typescript
// src/routes/health.routes.ts
import { Router, Request, Response } from 'express';
import { prisma } from '@/config/database';
import { redis } from '@/config/redis';

const router = Router();

interface HealthStatus {
  status: 'healthy' | 'unhealthy';
  timestamp: string;
  uptime: number;
  version: string;
  services: {
    database: 'connected' | 'disconnected';
    redis: 'connected' | 'disconnected';
  };
}

router.get('/', async (req: Request, res: Response) => {
  const health: HealthStatus = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: process.env.npm_package_version || '1.0.0',
    services: {
      database: 'disconnected',
      redis: 'disconnected',
    },
  };

  // Check database connection with timeout
  try {
    await Promise.race([
      prisma.$queryRaw`SELECT 1`,
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Database timeout')), 5000)
      )
    ]);
    health.services.database = 'connected';
  } catch (error) {
    console.error('Database health check failed:', error);
    health.status = 'unhealthy';
    health.services.database = 'disconnected';
  }

  // Check Redis connection with timeout
  try {
    await Promise.race([
      redis.ping(),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Redis timeout')), 5000)
      )
    ]);
    health.services.redis = 'connected';
  } catch (error) {
    console.error('Redis health check failed:', error);
    health.status = 'unhealthy';
    health.services.redis = 'disconnected';
  }

  const statusCode = health.status === 'healthy' ? 200 : 503;
  res.status(statusCode).json(health);
});

export default router;
```

🚀 Additional Recommendations
Optional Enhancements (if needed):
```typescript
// Add response caching for frequent health checks
router.get('/', async (req: Request, res: Response) => {
  // Set cache headers to prevent excessive database hits
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  
  // ... rest of your health check logic
});
```
Environment-Specific Considerations:
```typescript
// For production, you might want to add:
const isDevelopment = process.env.NODE_ENV === 'development';

// More detailed error info in development
if (isDevelopment && health.status === 'unhealthy') {
  (health as any).errors = {
    database: dbError?.message,
    redis: redisError?.message
  };
}
```
