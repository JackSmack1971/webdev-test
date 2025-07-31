# Modern Web Application Guidelines for AI Agents (2025)

*Place this file at the root of your project repository*

## Project Architecture Overview

This project follows modern web development best practices for 2025, emphasizing performance, security, and developer experience. The architecture is designed for scalability, maintainability, and optimal user experience.

## Technology Stack

### Frontend
- **Framework**: React 18+ with TypeScript and strict mode
- **UI Library**: Material UI v5+ or Tailwind CSS v3+
- **State Management**: Redux Toolkit with RTK Query for API state
- **Routing**: React Router v6+ with lazy loading
- **Build Tool**: Vite for optimal development experience and build performance

### Backend
- **Runtime**: Node.js 18+ with Express.js and TypeScript
- **API Design**: RESTful APIs with OpenAPI 3.0 documentation
- **Authentication**: JWT with RS256 algorithm and OAuth 2.0 integration
- **Validation**: Joi or Zod for request/response validation

### Database
- **Primary**: PostgreSQL 15+ for relational data with proper indexing
- **Cache**: Redis 7+ for session storage and application caching
- **Search**: ElasticSearch or vector database for semantic search
- **Migrations**: Database migrations with version control

### Infrastructure
- **Containerization**: Docker with multi-stage builds and .dockerignore
- **Orchestration**: Kubernetes with proper resource limits and health checks
- **CI/CD**: GitHub Actions with automated testing and security scanning
- **Monitoring**: OpenTelemetry for distributed tracing and metrics

## Project Structure

```
project-root/
├── frontend/                 # React application
│   ├── src/
│   │   ├── components/       # Reusable UI components (atomic design)
│   │   ├── features/         # Feature-specific components and logic
│   │   ├── hooks/           # Custom React hooks
│   │   ├── pages/           # Route components
│   │   ├── services/        # API integration and business logic
│   │   ├── store/           # Redux store configuration
│   │   ├── types/           # TypeScript type definitions
│   │   └── utils/           # Utility functions
│   ├── public/              # Static assets
│   └── tests/               # Frontend tests
├── backend/                 # Node.js API server
│   ├── src/
│   │   ├── controllers/     # Route handlers
│   │   ├── services/        # Business logic
│   │   ├── repositories/    # Data access layer
│   │   ├── models/          # Data models and schemas
│   │   ├── middleware/      # Express middleware
│   │   ├── config/          # Configuration management
│   │   └── utils/           # Utility functions
│   └── tests/               # Backend tests
├── shared/                  # Shared types and utilities
├── infrastructure/          # Docker, Kubernetes, CI/CD configs
├── docs/                    # Documentation and ADRs
└── scripts/                 # Build and deployment scripts
```

## Development Workflow

### Local Development
```bash
# Install dependencies
npm install

# Start development servers
npm run dev              # Starts both frontend and backend
npm run dev:frontend     # Frontend only (http://localhost:3000)
npm run dev:backend      # Backend only (http://localhost:8000)

# Run tests
npm test                 # All tests
npm run test:unit        # Unit tests only
npm run test:integration # Integration tests only
npm run test:e2e         # End-to-end tests

# Code quality
npm run lint             # ESLint + Prettier
npm run lint:fix         # Auto-fix linting issues
npm run type-check       # TypeScript type checking
```

### Git Workflow
- **Branches**: `main` (production), `develop` (integration), `feature/*`, `bugfix/*`
- **Commits**: Use conventional commits (feat, fix, docs, style, refactor, test, chore)
- **Pull Requests**: Require review, passing tests, and security scans
- **Merging**: Squash commits for clean history

## Code Style and Standards

### TypeScript Configuration
- **Strict Mode**: Enable all strict type checking options
- **Path Mapping**: Use absolute imports with path aliases
- **ESLint**: Airbnb config with TypeScript extensions
- **Prettier**: Consistent code formatting across the project

### Component Development (React)
```typescript
// Component Template
import React from 'react';
import { styled } from '@mui/material/styles';
import { Box, Typography, BoxProps } from '@mui/material';

interface ComponentProps extends BoxProps {
  title: string;
  description?: string;
  variant?: 'primary' | 'secondary';
}

const StyledContainer = styled(Box, {
  shouldForwardProp: (prop) => prop !== 'variant',
})<{ variant?: 'primary' | 'secondary' }>(({ theme, variant }) => ({
  padding: theme.spacing(2),
  borderRadius: theme.shape.borderRadius,
  backgroundColor: variant === 'primary' 
    ? theme.palette.primary.light 
    : theme.palette.grey[100],
}));

export const ExampleComponent: React.FC<ComponentProps> = ({
  title,
  description,
  variant = 'primary',
  ...boxProps
}) => {
  return (
    <StyledContainer variant={variant} {...boxProps}>
      <Typography variant="h6" component="h2">
        {title}
      </Typography>
      {description && (
        <Typography variant="body2" color="textSecondary">
          {description}
        </Typography>
      )}
    </StyledContainer>
  );
};
```

### API Development (Express)
```typescript
// Controller Template
import { Request, Response, NextFunction } from 'express';
import { UserService } from '../services/user.service';
import { CreateUserSchema } from '../schemas/user.schema';
import { HttpStatus } from '../constants/http-status';

export class UserController {
  constructor(private userService: UserService) {}

  async createUser(req: Request, res: Response, next: NextFunction) {
    try {
      const validatedData = CreateUserSchema.parse(req.body);
      const user = await this.userService.createUser(validatedData);
      
      res.status(HttpStatus.CREATED).json({
        success: true,
        data: user,
        message: 'User created successfully'
      });
    } catch (error) {
      next(error);
    }
  }
}
```

## Testing Strategy

### Testing Pyramid
- **Unit Tests**: 70% coverage targeting business logic and utilities
- **Integration Tests**: API endpoints and component integration
- **E2E Tests**: Critical user journeys and workflows
- **Performance Tests**: Core Web Vitals and API response times

### Testing Tools and Patterns
```typescript
// Unit Test Example (Jest + Testing Library)
import { render, screen, fireEvent } from '@testing-library/react';
import { ExampleComponent } from './ExampleComponent';

describe('ExampleComponent', () => {
  it('renders title and description correctly', () => {
    render(
      <ExampleComponent 
        title="Test Title" 
        description="Test Description" 
      />
    );
    
    expect(screen.getByRole('heading', { name: 'Test Title' })).toBeInTheDocument();
    expect(screen.getByText('Test Description')).toBeInTheDocument();
  });

  it('applies correct styling based on variant', () => {
    const { container } = render(
      <ExampleComponent title="Test" variant="secondary" />
    );
    
    expect(container.firstChild).toHaveStyle({
      backgroundColor: expect.any(String)
    });
  });
});
```

## Security Implementation

### Authentication & Authorization
- **JWT Strategy**: Use RS256 algorithm with proper key rotation
- **Password Security**: bcrypt with minimum 12 rounds
- **Session Management**: Secure, httpOnly cookies with SameSite protection
- **Rate Limiting**: Implement progressive rate limiting for API endpoints

### Input Validation and Sanitization
```typescript
// Validation Schema Example (Zod)
import { z } from 'zod';

export const CreateUserSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, 
      'Password must contain uppercase, lowercase, number and special character'),
  firstName: z.string().min(1, 'First name is required').max(50),
  lastName: z.string().min(1, 'Last name is required').max(50),
});

export type CreateUserData = z.infer<typeof CreateUserSchema>;
```

## Performance Optimization

### Frontend Performance
- **Code Splitting**: Implement route-based and component-based splitting
- **Image Optimization**: Use next-gen formats (AVIF, WebP) with fallbacks
- **Bundle Analysis**: Monitor and optimize bundle size regularly
- **Core Web Vitals**: Target LCP ≤ 2.0s, INP ≤ 100ms, CLS ≤ 0.1

### Backend Performance
- **Database Optimization**: Proper indexing and query optimization
- **Caching Strategy**: Multi-layer caching (Redis, CDN, browser)
- **Connection Pooling**: Optimize database connections
- **Async Processing**: Use queues for heavy operations

## Database Design

### Schema Design Principles
- **Normalization**: Apply appropriate normalization levels
- **Indexing**: Strategic indexing for query performance
- **Migrations**: Version-controlled database changes
- **Constraints**: Proper foreign keys and data integrity

```sql
-- Example Table Structure
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_deleted_at ON users(deleted_at) WHERE deleted_at IS NULL;
```

## API Design Standards

### RESTful API Conventions
- **Resource Naming**: Use plural nouns for collections (`/api/v1/users`)
- **HTTP Methods**: Proper use of GET, POST, PUT, PATCH, DELETE
- **Status Codes**: Appropriate HTTP status codes for responses
- **Versioning**: URL versioning (`/api/v1/`) for backward compatibility

### Response Format
```json
{
  "success": true,
  "data": {
    "id": "uuid",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe"
  },
  "message": "User retrieved successfully",
  "meta": {
    "timestamp": "2025-01-01T00:00:00Z",
    "version": "1.0.0"
  }
}
```

## Deployment and DevOps

### Docker Configuration
```dockerfile
# Multi-stage Dockerfile example
FROM node:18-alpine as builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:18-alpine as runtime
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY . .
EXPOSE 8000
CMD ["npm", "start"]
```

### CI/CD Pipeline
- **Testing**: Unit, integration, and E2E tests
- **Security**: SAST, DAST, and dependency scanning
- **Performance**: Bundle size and Core Web Vitals testing
- **Deployment**: Automated deployment with rollback capabilities

## Monitoring and Observability

### Logging Standards
```typescript
// Structured logging example
import { logger } from '../utils/logger';

export class UserService {
  async createUser(userData: CreateUserData) {
    logger.info('Creating new user', {
      correlationId: req.correlationId,
      email: userData.email,
      timestamp: new Date().toISOString()
    });

    try {
      const user = await this.userRepository.create(userData);
      logger.info('User created successfully', {
        correlationId: req.correlationId,
        userId: user.id
      });
      return user;
    } catch (error) {
      logger.error('Failed to create user', {
        correlationId: req.correlationId,
        error: error.message,
        stack: error.stack
      });
      throw error;
    }
  }
}
```

## Error Handling

### Global Error Handler
```typescript
// Express error handling middleware
export const errorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  logger.error('Unhandled error', {
    error: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    correlationId: req.correlationId
  });

  if (error instanceof ValidationError) {
    return res.status(400).json({
      success: false,
      error: 'VALIDATION_ERROR',
      message: error.message,
      details: error.details
    });
  }

  return res.status(500).json({
    success: false,
    error: 'INTERNAL_SERVER_ERROR',
    message: 'An unexpected error occurred'
  });
};
```

## Additional Guidelines

### Accessibility Requirements
- **WCAG 2.2 AA**: Minimum accessibility standard
- **Keyboard Navigation**: Full keyboard accessibility
- **Screen Reader**: Compatible with assistive technologies
- **Color Contrast**: Minimum 4.5:1 ratio for normal text

### Internationalization
- **i18n Library**: React-i18next for internationalization
- **Locale Support**: Support for multiple languages and regions
- **Date/Time**: Proper formatting for different locales
- **Currency**: Appropriate currency formatting

### Documentation Requirements
- **API Docs**: OpenAPI 3.0 specification with examples
- **Component Docs**: Storybook for UI component documentation
- **ADRs**: Architectural Decision Records for important decisions
- **README**: Clear setup and development instructions