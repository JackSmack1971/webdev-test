# Global Web Development Guidelines for AI Agents (2025)

*Place this file at `~/.codex/AGENTS.md` for personal global guidance*

## General Development Philosophy

- **Security First**: Always implement security as a core requirement, not an afterthought
- **Performance by Default**: Optimize for Core Web Vitals (LCP ≤ 2.0s, INP ≤ 100ms, CLS ≤ 0.1)
- **Accessibility Always**: Follow WCAG 2.2 AA standards as minimum requirement
- **Type Safety**: Use TypeScript strict mode for all new projects
- **AI-Augmented Development**: Leverage AI tools while maintaining human oversight

## Universal Code Style Standards

### General Conventions
- **Indentation**: 2 spaces (never tabs)
- **Line Length**: 100 characters maximum
- **Quotes**: Single quotes for strings, double quotes for JSX attributes
- **Semicolons**: Always use semicolons in JavaScript/TypeScript
- **Trailing Commas**: Always use trailing commas in multiline structures

### Naming Conventions
- **Files**: kebab-case for all files (e.g., `user-profile.component.ts`)
- **Directories**: kebab-case for directories
- **Classes**: PascalCase (e.g., `UserProfile`)
- **Interfaces**: PascalCase with descriptive names (e.g., `UserProfileData`)
- **Functions/Variables**: camelCase (e.g., `getUserProfile`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `MAX_RETRY_ATTEMPTS`)

## Technology Stack Preferences (2025)

### Frontend
- **Primary**: React 18+ with TypeScript, Material UI or Tailwind CSS
- **Alternative**: Vue.js 3+ with Composition API for smaller projects
- **Performance-Critical**: Svelte/SvelteKit for optimal bundle size

### Backend
- **Primary**: Node.js with Express and TypeScript
- **High-Performance**: Go for performance-critical services
- **AI/ML Integration**: Python with FastAPI for data science applications

### Database
- **Relational**: PostgreSQL for complex relationships and ACID compliance
- **Document**: MongoDB for flexible schemas and rapid development
- **Vector**: Pinecone or Weaviate for AI-powered applications
- **Cache**: Redis for session storage and high-speed caching

### Infrastructure
- **Containerization**: Docker with multi-stage builds
- **Orchestration**: Kubernetes for complex deployments
- **CI/CD**: GitHub Actions or GitLab CI over legacy Jenkins
- **Cloud**: Prefer cloud-native services with edge computing capabilities

## Security Standards

### Authentication & Authorization
- **Never store secrets in code or version control**
- **Use JWT with RS256 algorithm for tokens**
- **Implement passwordless authentication where possible**
- **Apply principle of least privilege for all access controls**

### Code Security
- **Validate all inputs at service boundaries**
- **Use parameterized queries for all database operations**
- **Implement proper error handling without exposing system details**
- **Run security scanning in CI/CD pipelines (SAST, DAST, SCA)**

### Dependencies
- **Pin exact versions for all dependencies**
- **Regularly audit and update dependencies**
- **Avoid deprecated or unmaintained packages**
- **Use dependency scanning tools (Snyk, Dependabot)**

## Testing Standards

### Test Pyramid
- **Unit Tests**: 70% coverage minimum, focus on business logic
- **Integration Tests**: API contracts and component interactions
- **E2E Tests**: Critical user journeys only
- **Performance Tests**: Core Web Vitals and load testing

### Testing Tools
- **JavaScript/TypeScript**: Jest, Vitest, or Testing Library
- **API Testing**: Supertest, Postman, or REST Assured
- **E2E Testing**: Playwright (preferred) or Cypress
- **Performance**: Lighthouse CI, k6, or WebPageTest

## Performance Optimization

### Frontend Performance
- **Implement code splitting and lazy loading**
- **Use next-gen image formats (AVIF, WebP)**
- **Optimize Core Web Vitals metrics**
- **Minimize JavaScript bundle size**
- **Use server components where appropriate**

### Backend Performance
- **Implement appropriate caching strategies**
- **Use connection pooling for databases**
- **Apply async processing for heavy operations**
- **Monitor and optimize database queries**

## AI Integration Guidelines

### AI-Powered Features
- **Implement vector databases for semantic search**
- **Use AI for content personalization and recommendations**
- **Apply AI-driven testing and code review**
- **Leverage AI for accessibility enhancements**

### AI Development Tools
- **Use GitHub Copilot for code assistance**
- **Implement AI-powered test generation**
- **Apply automated code review and optimization**
- **Use AI for documentation generation**

## Documentation Standards

- **Maintain README.md with clear setup instructions**
- **Document API endpoints with OpenAPI/Swagger**
- **Include architectural decision records (ADRs)**
- **Write clear comments for complex business logic**
- **Maintain changelog for all releases**

## Deployment and DevOps

### CI/CD Requirements
- **Automated testing on all pull requests**
- **Security scanning integrated into pipelines**
- **Automated deployment to staging environments**
- **Performance testing before production deployment**

### Infrastructure as Code
- **Use Terraform or CDK for infrastructure management**
- **Implement GitOps workflows for deployments**
- **Version control all configuration**
- **Apply least privilege principle for service accounts**

## Error Handling and Monitoring

### Error Handling
- **Use custom error classes that extend Error**
- **Log errors with appropriate context and correlation IDs**
- **Implement graceful degradation for non-critical failures**
- **Return consistent error responses from APIs**

### Observability
- **Implement distributed tracing with OpenTelemetry**
- **Use structured logging (JSON format)**
- **Monitor Core Web Vitals and business metrics**
- **Set up alerts for critical system health indicators**

## Accessibility Requirements

- **Follow WCAG 2.2 AA guidelines as minimum standard**
- **Test with screen readers and keyboard navigation**
- **Use semantic HTML and proper ARIA attributes**
- **Ensure color contrast ratios meet accessibility standards**
- **Include automated accessibility testing in CI/CD**

## Code Review Guidelines

### Review Checklist
- [ ] Security considerations addressed
- [ ] Performance impact evaluated
- [ ] Tests cover new functionality
- [ ] Documentation updated
- [ ] Accessibility requirements met
- [ ] Error handling implemented
- [ ] Code follows style guidelines

### Review Process
- **Require at least one approval for all changes**
- **Use conventional commit messages**
- **Squash commits before merging**
- **Include ticket/issue references in commits**

## Additional Resources

- **Style Guides**: Follow language-specific style guides (Airbnb, Google)
- **Security**: OWASP Top 10, security best practices documentation
- **Performance**: Core Web Vitals documentation, performance budgets
- **Accessibility**: WCAG guidelines, accessibility testing tools
