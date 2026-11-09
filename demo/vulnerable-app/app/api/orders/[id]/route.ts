import { createClient } from "@supabase/supabase-js";

// BUG: uses the service_role key (bypasses RLS) and never checks who is calling.
const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const { data } = await admin.from("orders").select("*").eq("id", params.id).single();
  return Response.json(data);
}
