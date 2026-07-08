import { cookies } from "next/headers";
import { redirect } from "next/navigation";

export default function EntryPage() {
  const cookieStore = cookies();
  const token = cookieStore.get("token")?.value;

  if (token) {
    // Has a session cookie, try to enter admin
    redirect("/admin");
  } else {
    // No session cookie, go to login
    redirect("/login");
  }
}
