import { createClient } from "@/lib/server-client";

// Fine: signs the caller in via cookies and lets RLS decide.
export async function GET() {
  const supabase = createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  const { data } = await supabase.from("notes").select("*").eq("user_id", user.id);
  return Response.json(data);
}
