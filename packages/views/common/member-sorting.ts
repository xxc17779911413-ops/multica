type MemberRegistrationState = {
  has_logged_in?: boolean;
};

// 2026-09-07 coder(lq): Treat only an explicit false as unregistered so older
// responses without the optional field remain visible with registered users.
export function compareMemberRegistration(
  left: MemberRegistrationState,
  right: MemberRegistrationState,
): number {
  return Number(left.has_logged_in === false) - Number(right.has_logged_in === false);
}
