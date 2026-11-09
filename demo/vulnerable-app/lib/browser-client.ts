import { createClient } from "@supabase/supabase-js";

// BUG: NEXT_PUBLIC_ variables are shipped to every visitor's browser.
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,
);
