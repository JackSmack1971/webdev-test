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
// tsconfig.json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "CommonJS",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
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
import rateLimit from 'express-rate-limit';
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
    hsts: {
      maxAge: 31536000,
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

  // Rate limiting
  app.use(rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
      error: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests, please try again later.',
    },
    standardHeaders: true,
    legacyHeaders: false,
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

async function startServer(): Promise<void> {
  try {
    // Initialize database connections
    await connectDatabase();
    await connectRedis();

    // Create Express application
    const app = createApp();

    // Start server
    const server = app.listen(config.port, () => {
      logger.info(`Server running on port ${config.port}`, {
        environment: config.env,
        port: config.port,
      });
    });

    // Graceful shutdown
    const gracefulShutdown = (signal: string) => {
      logger.info(`Received ${signal}, shutting down gracefully`);
      
      server.close(() => {
        logger.info('HTTP server closed');
        process.exit(0);
      });

      // Force close after 30 seconds
      setTimeout(() => {
        logger.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
      }, 30000);
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  } catch (error) {
    logger.error('Failed to start server', { error });
    process.exit(1);
  }
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', { promise, reason });
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', { error });
  process.exit(1);
});

startServer();
```

## Controller Pattern Implementation

### Base Controller Class
```typescript
// src/controllers/base.controller.ts
import { Request, Response, NextFunction } from 'express';
import { ZodSchema } from 'zod';
import { logger } from '@/utils/logger';
import { ApiResponse } from '@/types/api.types';

export abstract class BaseController {
  protected async executeAsync(
    req: Request,
    res: Response,
    next: NextFunction,
    operation: () => Promise<any>
  ): Promise<void> {
    try {
      const result = await operation();
      this.sendSuccess(res, result);
    } catch (error) {
      next(error);
    }
  }

  protected validateRequest<T>(
    schema: ZodSchema<T>,
    data: unknown
  ): T {
    return schema.parse(data);
  }

  protected sendSuccess<T>(
    res: Response,
    data: T,
    message = 'Operation successful',
    statusCode = 200
  ): void {
    const response: ApiResponse<T> = {
      success: true,
      data,
      message,
      meta: {
        timestamp: new Date().toISOString(),
      },
    };

    res.status(statusCode).json(response);
  }

  protected logOperation(
    req: Request,
    operation: string,
    data?: Record<string, any>
  ): void {
    logger.info(`Controller operation: ${operation}`, {
      correlationId: req.correlationId,
      userId: req.user?.id,
      operation,
      ...data,
    });
  }
}
```

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

  public createUser = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    this.logOperation(req, 'createUser');

    await this.executeAsync(req, res, next, async () => {
      const userData = this.validateRequest(CreateUserSchema, req.body);
      const user = await this.userService.createUser(userData);
      return user;
    });
  };

  public getUsers = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    this.logOperation(req, 'getUsers');

    await this.executeAsync(req, res, next, async () => {
      const query = this.validateRequest(GetUsersQuerySchema, req.query);
      const result = await this.userService.getUsers(query);
      return result;
    });
  };

  public getUserById = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    this.logOperation(req, 'getUserById', { userId: req.params.id });

    await this.executeAsync(req, res, next, async () => {
      const { id } = req.params;
      const user = await this.userService.getUserById(id);
      return user;
    });
  };

  public updateUser = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    this.logOperation(req, 'updateUser', { userId: req.params.id });

    await this.executeAsync(req, res, next, async () => {
      const { id } = req.params;
      const updateData = this.validateRequest(UpdateUserSchema, req.body);
      const user = await this.userService.updateUser(id, updateData);
      return user;
    });
  };

  public deleteUser = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    this.logOperation(req, 'deleteUser', { userId: req.params.id });

    await this.executeAsync(req, res, next, async () => {
      const { id } = req.params;
      await this.userService.deleteUser(id);
      return { message: 'User deleted successfully' };
    });
  };
}
```

## Service Layer Pattern

### Base Service Class
```typescript
// src/services/base.service.ts
import { logger } from '@/utils/logger';

export abstract class BaseService {
  protected logOperation(
    operation: string,
    data?: Record<string, any>,
    correlationId?: string
  ): void {
    logger.info(`Service operation: ${operation}`, {
      correlationId,
      service: this.constructor.name,
      operation,
      ...data,
    });
  }

  protected logError(
    operation: string,
    error: Error,
    data?: Record<string, any>,
    correlationId?: string
  ): void {
    logger.error(`Service error: ${operation}`, {
      correlationId,
      service: this.constructor.name,
      operation,
      error: error.message,
      stack: error.stack,
      ...data,
    });
  }
}
```

### User Service Implementation
```typescript
// src/services/user.service.ts
import bcrypt from 'bcrypt';
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

      // Hash password
      const saltRounds = 12;
      const passwordHash = await bcrypt.hash(userData.password, saltRounds);

      // Create user
      const user = await this.userRepository.create({
        ...userData,
        passwordHash,
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

      // Hash new password if provided
      let updatePayload = { ...updateData };
      if (updateData.password) {
        const saltRounds = 12;
        updatePayload.passwordHash = await bcrypt.hash(updateData.password, saltRounds);
        delete updatePayload.password;
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
import { PrismaClient } from '@prisma/client';
import { logger } from '@/utils/logger';

export abstract class BaseRepository {
  constructor(protected prisma: PrismaClient) {}

  protected logQuery(
    operation: string,
    model: string,
    data?: Record<string, any>
  ): void {
    logger.debug(`Database operation: ${operation}`, {
      repository: this.constructor.name,
      model,
      operation,
      ...data,
    });
  }

  protected handleError(
    operation: string,
    error: Error,
    data?: Record<string, any>
  ): never {
    logger.error(`Database error: ${operation}`, {
      repository: this.constructor.name,
      operation,
      error: error.message,
      ...data,
    });
    throw error;
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
      this.handleError('create', error as Error, { email: userData.email });
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
    }
  }

  public async delete(id: string): Promise<void> {
    this.logQuery('delete', 'User', { id });

    try {
      await this.prisma.user.delete({
        where: { id },
      });
    } catch (error) {
      this.handleError('delete', error as Error, { id });
    }
  }
}
```

## Type Definitions

### API Types
```typescript
// src/types/api.types.ts
export interface ApiResponse<T = any> {
  success: boolean;
  data: T;
  message?: string;
  errors?: Record<string, string[]>;
  meta?: {
    timestamp: string;
    version?: string;
  };
}

export interface PaginationQuery {
  page?: number;
  limit?: number;
}

export interface PaginationMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: PaginationMeta;
}
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
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
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
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
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

      const token = authHeader.substring(7);
      
      const decoded = jwt.verify(token, config.jwt.publicKey, {
        algorithms: ['RS256'],
      }) as JwtPayload;

      // Verify user still exists
      const user = await this.userRepository.findById(decoded.userId);
      if (!user) {
        throw new UnauthorizedError('User not found');
      }

      // Attach user to request
      req.user = {
        id: user.id,
        email: user.email,
        role: user.role,
      };

      next();
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        next(new UnauthorizedError('Invalid token'));
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
    if (error.code === 'P2002') {
      return res.status(409).json({
        success: false,
        error: 'CONFLICT',
        message: 'Resource already exists',
        meta: {
          timestamp: new Date().toISOString(),
        },
      });
    }

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
  const statusCode = process.env.NODE_ENV === 'production' ? 500 : 500;
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

// Mock dependencies
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
    jest.clearAllMocks();
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

      mockUserRepository.findByEmail.mockResolvedValue(null);
      mockUserRepository.create.mockResolvedValue(createdUser);
      mockEmailService.sendWelcomeEmail.mockResolvedValue(undefined);

      const result = await userService.createUser(userData);

      expect(mockUserRepository.findByEmail).toHaveBeenCalledWith(userData.email);
      expect(mockUserRepository.create).toHaveBeenCalledWith({
        ...userData,
        passwordHash: expect.any(String),
      });
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
    // Clean up database
    await prisma.user.deleteMany();
  });

  afterAll(async () => {
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
      // Create test users
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
  authorId  String
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
    });
  });
}

prisma.$on('error', (e) => {
  logger.error('Database Error', {
    target: e.target,
    message: e.message,
  });
});

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

class JWTService {
  private privateKey: string;
  private publicKey: string;

  constructor() {
    if (process.env.NODE_ENV === 'production') {
      // In production, use environment variables
      this.privateKey = process.env.JWT_PRIVATE_KEY?.replace(/\\n/g, '\n') || '';
      this.publicKey = process.env.JWT_PUBLIC_KEY?.replace(/\\n/g, '\n') || '';
    } else {
      // In development, use local key files
      this.privateKey = fs.readFileSync(
        path.join(process.cwd(), 'keys', 'private.pem'),
        'utf8'
      );
      this.publicKey = fs.readFileSync(
        path.join(process.cwd(), 'keys', 'public.pem'),
        'utf8'
      );
    }
  }

  public generateTokens(payload: {
    userId: string;
    email: string;
    role: string;
  }): { accessToken: string; refreshToken: string } {
    const accessToken = jwt.sign(payload, this.privateKey, {
      algorithm: 'RS256',
      expiresIn: config.jwt.accessTokenExpiry,
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
    });

    const refreshToken = jwt.sign(
      { userId: payload.userId },
      this.privateKey,
      {
        algorithm: 'RS256',
        expiresIn: config.jwt.refreshTokenExpiry,
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
      }
    );

    return { accessToken, refreshToken };
  }

  public verifyToken(token: string): any {
    return jwt.verify(token, this.publicKey, {
      algorithms: ['RS256'],
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
    });
  }

  public getPublicKey(): string {
    return this.publicKey;
  }
}

export const jwtService = new JWTService();
```

### Rate Limiting Configuration
```typescript
// src/middleware/rate-limit.middleware.ts
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import { redis } from '@/config/redis';

// General API rate limiting
export const generalLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args: string[]) => redis.call(...args),
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
    sendCommand: (...args: string[]) => redis.call(...args),
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
    sendCommand: (...args: string[]) => redis.call(...args),
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

// Load environment variables
dotenv.config();

// Environment validation schema
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

// Validate environment variables
const env = envSchema.parse(process.env);

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
    privateKey: env.JWT_PRIVATE_KEY.replace(/\\n/g, '\n'),
    publicKey: env.JWT_PUBLIC_KEY.replace(/\\n/g, '\n'),
    accessTokenExpiry: env.JWT_ACCESS_TOKEN_EXPIRY,
    refreshTokenExpiry: env.JWT_REFRESH_TOKEN_EXPIRY,
    issuer: env.JWT_ISSUER,
    audience: env.JWT_AUDIENCE,
  },
  
  cors: {
    origins: env.CORS_ORIGINS.split(',').map(origin => origin.trim()),
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
# Multi-stage Dockerfile for Node.js application
FROM node:20-alpine AS base

# Install dependencies for native modules
RUN apk add --no-cache libc6-compat

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY prisma ./prisma/

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Build stage
FROM base AS builder

WORKDIR /app

# Copy source code
COPY . .

# Install all dependencies (including dev dependencies)
RUN npm ci

# Generate Prisma client
RUN npx prisma generate

# Build the application
RUN npm run build

# Production stage
FROM node:20-alpine AS runner

WORKDIR /app

# Create non-root user
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nodejs

# Copy built application
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/package.json ./package.json
COPY --from=builder --chown=nodejs:nodejs /app/prisma ./prisma

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8000/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) }).on('error', () => process.exit(1))"

# Start the application
CMD ["npm", "start"]
```

### Docker Compose for Development
```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      - NODE_ENV=development
      - DATABASE_URL=postgresql://postgres:password@postgres:5432/app_db
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
    volumes:
      - .:/app
      - /app/node_modules
    command: npm run dev

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

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

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

export const logger = winston.createLogger({
  level: config.logging.level,
  format: logFormat,
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
    }),
    new winston.transports.File({
      filename: 'logs/combined.log',
    }),
  ],
});

// Don't log to console in production
if (config.env === 'production') {
  logger.clear();
  logger.add(new winston.transports.File({
    filename: 'logs/error.log',
    level: 'error',
  }));
  logger.add(new winston.transports.File({
    filename: 'logs/combined.log',
  }));
}
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

  try {
    // Check database connection
    await prisma.$queryRaw`SELECT 1`;
    health.services.database = 'connected';
  } catch (error) {
    health.status = 'unhealthy';
    health.services.database = 'disconnected';
  }

  try {
    // Check Redis connection
    await redis.ping();
    health.services.redis = 'connected';
  } catch (error) {
    health.status = 'unhealthy';
    health.services.redis = 'disconnected';
  }

  const statusCode = health.status === 'healthy' ? 200 : 503;
  res.status(statusCode).json(health);
});

export default router;
```