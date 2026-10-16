import { QueryClient } from '@tanstack/react-query'

// One client for the whole app, exported so logout can clear every cached
// response (N22): the next person in the same tab must not see the last
// user's data, not even for a moment.
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})
