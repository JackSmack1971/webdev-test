# React + TypeScript Frontend Guidelines for AI Agents (2025)

*Place this file in your React frontend directory: `frontend/AGENTS.md`*

## Technology Stack

- **React**: 18.3+ with Concurrent Features and Server Components
- **TypeScript**: 5.0+ with strict mode enabled
- **Build Tool**: Vite 5+ for optimal development experience
- **UI Framework**: Material UI v5+ or Tailwind CSS v3+
- **State Management**: Redux Toolkit with RTK Query
- **Testing**: Vitest + React Testing Library + Playwright
- **Bundler**: Modern ES modules with tree shaking

## Project Structure

```
frontend/
├── src/
│   ├── components/          # Reusable UI components (atomic design)
│   │   ├── atoms/          # Basic building blocks (Button, Input, etc.)
│   │   ├── molecules/      # Composite components (SearchBox, etc.)
│   │   └── organisms/      # Complex components (Header, Sidebar, etc.)
│   ├── features/           # Feature-specific components and logic
│   │   ├── auth/          # Authentication feature
│   │   ├── dashboard/     # Dashboard feature
│   │   └── profile/       # User profile feature
│   ├── hooks/             # Custom React hooks
│   ├── pages/             # Route components
│   ├── services/          # API integration and business logic
│   ├── store/             # Redux store configuration
│   ├── types/             # TypeScript type definitions
│   ├── utils/             # Utility functions
│   ├── assets/            # Static assets (images, fonts, etc.)
│   ├── theme/             # UI theme configuration
│   ├── App.tsx            # Root application component
│   └── main.tsx           # Application entry point
├── public/                # Static public assets
├── tests/                 # Test files and utilities
│   ├── __mocks__/         # Mock files
│   ├── fixtures/          # Test data fixtures
│   └── setup.ts           # Test configuration
├── .env.example           # Environment variables template
├── vite.config.ts         # Vite configuration
└── tsconfig.json          # TypeScript configuration
```

## React Component Development

### Component Architecture Principles

1. **Functional Components**: Always use functional components with hooks
2. **Single Responsibility**: Each component should have one clear purpose
3. **Composition over Inheritance**: Prefer component composition
4. **Props Interface**: Always define explicit TypeScript interfaces for props
5. **Forward Refs**: Use forwardRef for components that need ref access

### Component Template

```typescript
import React, { forwardRef, useState, useCallback } from 'react';
import { styled } from '@mui/material/styles';
import { Box, Typography, Button, BoxProps } from '@mui/material';

// Props interface with proper TypeScript typing
interface FeatureCardProps extends Omit<BoxProps, 'title'> {
  title: string;
  description?: string;
  variant?: 'primary' | 'secondary' | 'outlined';
  onAction?: () => void;
  isLoading?: boolean;
  disabled?: boolean;
  icon?: React.ReactNode;
  'data-testid'?: string;
}

// Styled components with theme integration
const StyledCard = styled(Box, {
  shouldForwardProp: (prop) => !['variant', 'isLoading'].includes(prop as string),
})<{ variant: FeatureCardProps['variant']; isLoading?: boolean }>(
  ({ theme, variant, isLoading }) => ({
    padding: theme.spacing(3),
    borderRadius: theme.shape.borderRadius * 2,
    border: `1px solid ${theme.palette.divider}`,
    transition: theme.transitions.create(['transform', 'box-shadow'], {
      duration: theme.transitions.duration.short,
    }),
    cursor: isLoading ? 'not-allowed' : 'pointer',
    opacity: isLoading ? 0.7 : 1,
    
    ...(variant === 'primary' && {
      backgroundColor: theme.palette.primary.main,
      color: theme.palette.primary.contrastText,
      '&:hover': {
        transform: 'translateY(-2px)',
        boxShadow: theme.shadows[4],
      },
    }),
    
    ...(variant === 'secondary' && {
      backgroundColor: theme.palette.secondary.main,
      color: theme.palette.secondary.contrastText,
    }),
    
    ...(variant === 'outlined' && {
      backgroundColor: 'transparent',
      borderColor: theme.palette.primary.main,
    }),
  })
);

// Main component with forwardRef for ref forwarding
export const FeatureCard = forwardRef<HTMLDivElement, FeatureCardProps>(
  ({
    title,
    description,
    variant = 'primary',
    onAction,
    isLoading = false,
    disabled = false,
    icon,
    'data-testid': testId,
    ...boxProps
  }, ref) => {
    const [isHovered, setIsHovered] = useState(false);

    const handleClick = useCallback(() => {
      if (!disabled && !isLoading && onAction) {
        onAction();
      }
    }, [disabled, isLoading, onAction]);

    const handleMouseEnter = useCallback(() => {
      setIsHovered(true);
    }, []);

    const handleMouseLeave = useCallback(() => {
      setIsHovered(false);
    }, []);

    return (
      <StyledCard
        ref={ref}
        variant={variant}
        isLoading={isLoading}
        onClick={handleClick}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        data-testid={testId}
        role="button"
        tabIndex={disabled || isLoading ? -1 : 0}
        aria-disabled={disabled || isLoading}
        {...boxProps}
      >
        {icon && (
          <Box mb={2} display="flex" alignItems="center">
            {icon}
          </Box>
        )}
        
        <Typography 
          variant="h6" 
          component="h3" 
          gutterBottom
          sx={{ fontWeight: 600 }}
        >
          {title}
        </Typography>
        
        {description && (
          <Typography 
            variant="body2" 
            color="textSecondary"
            sx={{ mb: 2 }}
          >
            {description}
          </Typography>
        )}
        
        {onAction && (
          <Button
            variant={variant === 'outlined' ? 'contained' : 'outlined'}
            size="small"
            disabled={disabled || isLoading}
            sx={{ mt: 'auto' }}
          >
            {isLoading ? 'Loading...' : 'Learn More'}
          </Button>
        )}
      </StyledCard>
    );
  }
);

FeatureCard.displayName = 'FeatureCard';
```

## TypeScript Configuration for React

### Strict TypeScript Setup
```json
// tsconfig.json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "allowJs": true,
    "skipLibCheck": true,
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true,
    "strict": true,
    "noFallthroughCasesInSwitch": true,
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"],
      "@/components/*": ["src/components/*"],
      "@/hooks/*": ["src/hooks/*"],
      "@/utils/*": ["src/utils/*"],
      "@/types/*": ["src/types/*"]
    }
  },
  "include": ["src", "tests"],
  "exclude": ["node_modules", "dist"]
}
```

### Advanced TypeScript Patterns

```typescript
// Utility types for React development
export type PropsWithTestId<T = {}> = T & {
  'data-testid'?: string;
};

export type ComponentWithChildren<T = {}> = T & {
  children?: React.ReactNode;
};

// Generic API response type
export interface ApiResponse<T> {
  data: T;
  success: boolean;
  message?: string;
  errors?: Record<string, string[]>;
}

// Event handler types
export type FormSubmitHandler<T = HTMLFormElement> = (
  event: React.FormEvent<T>
) => void;

export type ButtonClickHandler = (
  event: React.MouseEvent<HTMLButtonElement>
) => void;

// Hook return types
export interface UseApiState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

// Component props with discriminated unions
export type NotificationProps = 
  | {
      type: 'success';
      message: string;
      autoClose?: boolean;
    }
  | {
      type: 'error';
      message: string;
      details?: string[];
      retry?: () => void;
    }
  | {
      type: 'info';
      message: string;
      action?: {
        label: string;
        onClick: () => void;
      };
    };
```

## State Management with Redux Toolkit

### Store Configuration
```typescript
// store/index.ts
import { configureStore } from '@reduxjs/toolkit';
import { setupListeners } from '@reduxjs/toolkit/query';
import { authApi } from './api/authApi';
import { userApi } from './api/userApi';
import authSlice from './slices/authSlice';
import uiSlice from './slices/uiSlice';

export const store = configureStore({
  reducer: {
    auth: authSlice,
    ui: uiSlice,
    [authApi.reducerPath]: authApi.reducer,
    [userApi.reducerPath]: userApi.reducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: ['persist/PERSIST'],
      },
    })
    .concat(authApi.middleware)
    .concat(userApi.middleware),
});

setupListeners(store.dispatch);

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
```

### RTK Query API Slice
```typescript
// store/api/userApi.ts
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { RootState } from '../index';

export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  avatar?: string;
  role: 'admin' | 'user' | 'moderator';
  createdAt: string;
  updatedAt: string;
}

export interface CreateUserRequest {
  email: string;
  firstName: string;
  lastName: string;
  password: string;
}

export interface UpdateUserRequest {
  firstName?: string;
  lastName?: string;
  avatar?: string;
}

export const userApi = createApi({
  reducerPath: 'userApi',
  baseQuery: fetchBaseQuery({
    baseUrl: '/api/v1/users',
    prepareHeaders: (headers, { getState }) => {
      const token = (getState() as RootState).auth.token;
      if (token) {
        headers.set('authorization', `Bearer ${token}`);
      }
      return headers;
    },
  }),
  tagTypes: ['User'],
  endpoints: (builder) => ({
    getUsers: builder.query<User[], { page?: number; limit?: number }>({
      query: ({ page = 1, limit = 10 } = {}) => 
        `?page=${page}&limit=${limit}`,
      providesTags: ['User'],
    }),
    getUserById: builder.query<User, string>({
      query: (id) => `/${id}`,
      providesTags: (result, error, id) => [{ type: 'User', id }],
    }),
    createUser: builder.mutation<User, CreateUserRequest>({
      query: (newUser) => ({
        url: '',
        method: 'POST',
        body: newUser,
      }),
      invalidatesTags: ['User'],
    }),
    updateUser: builder.mutation<User, { id: string; updates: UpdateUserRequest }>({
      query: ({ id, updates }) => ({
        url: `/${id}`,
        method: 'PATCH',
        body: updates,
      }),
      invalidatesTags: (result, error, { id }) => [{ type: 'User', id }],
    }),
    deleteUser: builder.mutation<void, string>({
      query: (id) => ({
        url: `/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['User'],
    }),
  }),
});

export const {
  useGetUsersQuery,
  useGetUserByIdQuery,
  useCreateUserMutation,
  useUpdateUserMutation,
  useDeleteUserMutation,
} = userApi;
```

## Custom Hooks Development

### API Integration Hook
```typescript
// hooks/useApi.ts
import { useState, useEffect, useCallback } from 'react';

export interface UseApiOptions<T> {
  initialData?: T;
  onSuccess?: (data: T) => void;
  onError?: (error: Error) => void;
  immediate?: boolean;
}

export function useApi<T>(
  apiFunction: () => Promise<T>,
  options: UseApiOptions<T> = {}
) {
  const { initialData, onSuccess, onError, immediate = true } = options;
  
  const [data, setData] = useState<T | null>(initialData || null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const execute = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const result = await apiFunction();
      setData(result);
      onSuccess?.(result);
      return result;
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Unknown error');
      setError(error);
      onError?.(error);
      throw error;
    } finally {
      setLoading(false);
    }
  }, [apiFunction, onSuccess, onError]);

  useEffect(() => {
    if (immediate) {
      execute();
    }
  }, [execute, immediate]);

  return {
    data,
    loading,
    error,
    execute,
    refetch: execute,
  };
}
```

### Form Management Hook
```typescript
// hooks/useForm.ts
import { useState, useCallback, ChangeEvent } from 'react';

export interface UseFormOptions<T> {
  initialValues: T;
  validate?: (values: T) => Partial<Record<keyof T, string>>;
  onSubmit: (values: T) => Promise<void> | void;
}

export function useForm<T extends Record<string, any>>({
  initialValues,
  validate,
  onSubmit,
}: UseFormOptions<T>) {
  const [values, setValues] = useState<T>(initialValues);
  const [errors, setErrors] = useState<Partial<Record<keyof T, string>>>({});
  const [touched, setTouched] = useState<Partial<Record<keyof T, boolean>>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleChange = useCallback((
    event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    const { name, value, type } = event.target;
    const finalValue = type === 'checkbox' 
      ? (event.target as HTMLInputElement).checked 
      : value;

    setValues((prev) => ({
      ...prev,
      [name]: finalValue,
    }));

    if (touched[name as keyof T]) {
      const newErrors = validate?.({ ...values, [name]: finalValue }) || {};
      setErrors((prev) => ({
        ...prev,
        [name]: newErrors[name as keyof T],
      }));
    }
  }, [values, validate, touched]);

  const handleBlur = useCallback((field: keyof T) => {
    setTouched((prev) => ({ ...prev, [field]: true }));
    
    if (validate) {
      const newErrors = validate(values);
      setErrors((prev) => ({
        ...prev,
        [field]: newErrors[field],
      }));
    }
  }, [values, validate]);

  const handleSubmit = useCallback(async (event: React.FormEvent) => {
    event.preventDefault();
    
    const allErrors = validate?.(values) || {};
    setErrors(allErrors);
    setTouched(
      Object.keys(values).reduce(
        (acc, key) => ({ ...acc, [key]: true }),
        {}
      )
    );

    if (Object.keys(allErrors).length === 0) {
      setIsSubmitting(true);
      try {
        await onSubmit(values);
      } finally {
        setIsSubmitting(false);
      }
    }
  }, [values, validate, onSubmit]);

  const reset = useCallback(() => {
    setValues(initialValues);
    setErrors({});
    setTouched({});
    setIsSubmitting(false);
  }, [initialValues]);

  return {
    values,
    errors,
    touched,
    isSubmitting,
    handleChange,
    handleBlur,
    handleSubmit,
    reset,
  };
}
```

## Testing Standards

### Component Testing with React Testing Library
```typescript
// tests/components/FeatureCard.test.tsx
import { render, screen, fireEvent } from '@testing-library/react';
import { vi } from 'vitest';
import { ThemeProvider } from '@mui/material/styles';
import { FeatureCard } from '@/components/molecules/FeatureCard';
import { theme } from '@/theme';

const renderWithTheme = (component: React.ReactElement) => {
  return render(
    <ThemeProvider theme={theme}>
      {component}
    </ThemeProvider>
  );
};

describe('FeatureCard', () => {
  const defaultProps = {
    title: 'Test Feature',
    description: 'This is a test description',
    'data-testid': 'feature-card',
  };

  it('renders title and description correctly', () => {
    renderWithTheme(<FeatureCard {...defaultProps} />);
    
    expect(screen.getByRole('heading', { name: 'Test Feature' })).toBeInTheDocument();
    expect(screen.getByText('This is a test description')).toBeInTheDocument();
  });

  it('calls onAction when clicked', () => {
    const mockOnAction = vi.fn();
    renderWithTheme(
      <FeatureCard {...defaultProps} onAction={mockOnAction} />
    );
    
    fireEvent.click(screen.getByTestId('feature-card'));
    expect(mockOnAction).toHaveBeenCalledTimes(1);
  });

  it('shows loading state correctly', () => {
    renderWithTheme(
      <FeatureCard {...defaultProps} isLoading onAction={vi.fn()} />
    );
    
    expect(screen.getByText('Loading...')).toBeInTheDocument();
    expect(screen.getByTestId('feature-card')).toHaveAttribute('aria-disabled', 'true');
  });

  it('applies correct variant styling', () => {
    const { container } = renderWithTheme(
      <FeatureCard {...defaultProps} variant="secondary" />
    );
    
    const card = container.firstChild as HTMLElement;
    expect(card).toHaveStyle({ backgroundColor: expect.any(String) });
  });

  it('handles keyboard navigation', () => {
    const mockOnAction = vi.fn();
    renderWithTheme(
      <FeatureCard {...defaultProps} onAction={mockOnAction} />
    );
    
    const card = screen.getByTestId('feature-card');
    expect(card).toHaveAttribute('tabIndex', '0');
    
    fireEvent.keyDown(card, { key: 'Enter' });
    expect(mockOnAction).toHaveBeenCalledTimes(1);
  });
});
```

### Hook Testing
```typescript
// tests/hooks/useApi.test.ts
import { renderHook, waitFor } from '@testing-library/react';
import { vi } from 'vitest';
import { useApi } from '@/hooks/useApi';

describe('useApi', () => {
  it('should fetch data successfully', async () => {
    const mockData = { id: 1, name: 'Test' };
    const mockApiFunction = vi.fn().mockResolvedValue(mockData);
    
    const { result } = renderHook(() => 
      useApi(mockApiFunction, { immediate: true })
    );

    expect(result.current.loading).toBe(true);
    expect(result.current.data).toBe(null);

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
      expect(result.current.data).toEqual(mockData);
      expect(result.current.error).toBe(null);
    });
  });

  it('should handle errors correctly', async () => {
    const mockError = new Error('API Error');
    const mockApiFunction = vi.fn().mockRejectedValue(mockError);
    
    const { result } = renderHook(() => 
      useApi(mockApiFunction, { immediate: true })
    );

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
      expect(result.current.data).toBe(null);
      expect(result.current.error).toEqual(mockError);
    });
  });
});
```

## Performance Optimization

### Code Splitting and Lazy Loading
```typescript
// Lazy load components
import { lazy, Suspense } from 'react';
import { CircularProgress, Box } from '@mui/material';

const Dashboard = lazy(() => import('@/pages/Dashboard'));
const Profile = lazy(() => import('@/pages/Profile'));
const Settings = lazy(() => import('@/pages/Settings'));

// Loading component
const LoadingFallback = () => (
  <Box 
    display="flex" 
    justifyContent="center" 
    alignItems="center" 
    minHeight="200px"
  >
    <CircularProgress />
  </Box>
);

// Route configuration with lazy loading
export const routes = [
  {
    path: '/dashboard',
    element: (
      <Suspense fallback={<LoadingFallback />}>
        <Dashboard />
      </Suspense>
    ),
  },
  {
    path: '/profile',
    element: (
      <Suspense fallback={<LoadingFallback />}>
        <Profile />
      </Suspense>
    ),
  },
];
```

### Memoization Patterns
```typescript
import { memo, useMemo, useCallback } from 'react';

// Memoized component
export const ExpensiveComponent = memo<{
  data: ComplexData[];
  onItemClick: (id: string) => void;
}>(({ data, onItemClick }) => {
  // Expensive computation memoized
  const processedData = useMemo(() => {
    return data.map(item => ({
      ...item,
      computed: expensiveCalculation(item),
    }));
  }, [data]);

  // Stable callback reference
  const handleClick = useCallback((id: string) => {
    onItemClick(id);
  }, [onItemClick]);

  return (
    <div>
      {processedData.map(item => (
        <div key={item.id} onClick={() => handleClick(item.id)}>
          {item.computed}
        </div>
      ))}
    </div>
  );
});
```

## Accessibility Implementation

### ARIA and Semantic HTML
```typescript
// Accessible component example
export const AccessibleModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}> = ({ isOpen, onClose, title, children }) => {
  const titleId = useId();
  const descriptionId = useId();

  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }

    return () => {
      document.body.style.overflow = 'unset';
    };
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      aria-describedby={descriptionId}
      className="modal-overlay"
      onClick={onClose}
    >
      <div
        className="modal-content"
        onClick={(e) => e.stopPropagation()}
      >
        <header>
          <h2 id={titleId}>{title}</h2>
          <button
            onClick={onClose}
            aria-label="Close modal"
            className="close-button"
          >
            ×
          </button>
        </header>
        <div id={descriptionId}>
          {children}
        </div>
      </div>
    </div>
  );
};
```

## Error Handling and Boundaries

### Error Boundary Implementation
```typescript
// components/ErrorBoundary.tsx
import React, { Component, ErrorInfo, ReactNode } from 'react';
import { Button, Container, Typography, Box } from '@mui/material';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  onError?: (error: Error, errorInfo: ErrorInfo) => void;
}

interface State {
  hasError: boolean;
  error?: Error;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
    this.props.onError?.(error, errorInfo);
  }

  private handleRetry = () => {
    this.setState({ hasError: false, error: undefined });
  };

  public render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <Container maxWidth="sm">
          <Box textAlign="center" py={4}>
            <Typography variant="h4" gutterBottom color="error">
              Something went wrong
            </Typography>
            <Typography variant="body1" paragraph>
              We're sorry, but something unexpected happened. Please try again.
            </Typography>
            {process.env.NODE_ENV === 'development' && (
              <Typography variant="body2" component="pre" sx={{ mt: 2, p: 2, bgcolor: 'grey.100' }}>
                {this.state.error?.stack}
              </Typography>
            )}
            <Button
              variant="contained"
              onClick={this.handleRetry}
              sx={{ mt: 2 }}
            >
              Try Again
            </Button>
          </Box>
        </Container>
      );
    }

    return this.props.children;
  }
}
```

## Build and Development Configuration

### Vite Configuration
```typescript
// vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

export default defineConfig({
  plugins: [
    react({
      // Enable React Fast Refresh
      fastRefresh: true,
    }),
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
      '@/components': resolve(__dirname, 'src/components'),
      '@/hooks': resolve(__dirname, 'src/hooks'),
      '@/utils': resolve(__dirname, 'src/utils'),
      '@/types': resolve(__dirname, 'src/types'),
    },
  },
  build: {
    // Optimize build output
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom'],
          ui: ['@mui/material', '@mui/icons-material'],
          router: ['react-router-dom'],
          state: ['@reduxjs/toolkit', 'react-redux'],
        },
      },
    },
    // Enable source maps for production debugging
    sourcemap: true,
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
});
```

## Additional Best Practices

### Environment Management
```typescript
// utils/env.ts
const requiredEnvVars = [
  'VITE_API_BASE_URL',
  'VITE_APP_NAME',
] as const;

type RequiredEnvVar = typeof requiredEnvVars[number];

class EnvironmentError extends Error {
  constructor(missingVars: string[]) {
    super(`Missing required environment variables: ${missingVars.join(', ')}`);
    this.name = 'EnvironmentError';
  }
}

function validateEnvironment() {
  const missing = requiredEnvVars.filter(
    (varName) => !import.meta.env[varName]
  );

  if (missing.length > 0) {
    throw new EnvironmentError(missing);
  }
}

// Call during app initialization
validateEnvironment();

export const env = {
  API_BASE_URL: import.meta.env.VITE_API_BASE_URL,
  APP_NAME: import.meta.env.VITE_APP_NAME,
  IS_DEVELOPMENT: import.meta.env.DEV,
  IS_PRODUCTION: import.meta.env.PROD,
} as const;
```

### Internationalization Setup
```typescript
// i18n/index.ts
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

import en from './locales/en.json';
import es from './locales/es.json';
import fr from './locales/fr.json';

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: 'en',
    debug: process.env.NODE_ENV === 'development',
    
    interpolation: {
      escapeValue: false,
    },
    
    resources: {
      en: { translation: en },
      es: { translation: es },
      fr: { translation: fr },
    },
  });

export default i18n;
```