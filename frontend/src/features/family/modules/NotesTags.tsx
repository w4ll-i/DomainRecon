import { Plus, Save, X } from "lucide-react";
import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { errorDetail } from "../../../api/client";
import { useUpdateMeta } from "../../../api/queries";
import type { ScanResponse } from "../../../api/types";
import { useToast } from "../../../components/Toasts";
import { charCount } from "../../../lib/format";
import styles from "./modules.module.css";

// Bornes de ScanMetaUpdate (API) : vérifiées avant l'envoi, le serveur restant juge.
const MAX_TAGS = 20;
const MAX_TAG_LENGTH = 50;
const MAX_NOTES = 10_000;

// Approximation de casefold() (Python, côté API) : « ß » et « SS » se confondent.
const fold = (value: string) => value.toUpperCase().toLowerCase();

// Monté avec key={scan.id} : les notes en cours de saisie ne sont réinitialisées
// qu'au changement de scan.
export function NotesTags({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const toast = useToast();
  const update = useUpdateMeta(scan.id);
  const [tag, setTag] = useState("");
  const [tagError, setTagError] = useState<string | null>(null);
  const [notes, setNotes] = useState(scan.notes ?? "");
  const [notesError, setNotesError] = useState<string | null>(null);
  const tags = useMemo(() => scan.tags ?? [], [scan.tags]);
  const tagInput = useRef<HTMLInputElement>(null);
  const removeButtons = useRef<Array<HTMLButtonElement | null>>([]);
  // Position du tag retiré : le focus passe au voisin une fois la liste à jour.
  const focusAfterRemoval = useRef<number | null>(null);

  useEffect(() => {
    const index = focusAfterRemoval.current;
    if (index === null) return;
    focusAfterRemoval.current = null;
    (removeButtons.current[Math.min(index, tags.length - 1)] ?? tagInput.current)?.focus();
  }, [tags]);

  // Refus du serveur (422 : le detail est déjà traduit dans la langue de
  // l'interface) : affiché tel quel près du champ, la saisie est conservée.
  const save = (
    body: { tags?: string[]; notes?: string },
    { onSaved, onFailed }: { onSaved?: () => void; onFailed: (message: string) => void },
  ) =>
    update.mutate(body, {
      onSuccess: () => onSaved?.(),
      onError: (error) => {
        focusAfterRemoval.current = null;
        onFailed(t("identity.meta.error", { detail: errorDetail(error) }));
      },
    });

  // Refus côté client : message lié au champ (aria-invalid / aria-describedby),
  // annoncé une seule fois, effacé dès la saisie suivante.
  const addTag = (event: FormEvent) => {
    event.preventDefault();
    const value = tag.trim();
    if (!value || update.isPending) return;
    if (charCount(value) > MAX_TAG_LENGTH) {
      setTagError(t("identity.tags.tooLong", { max: MAX_TAG_LENGTH }));
      return;
    }
    if (tags.some((existing) => fold(existing) === fold(value))) {
      setTagError(t("identity.tags.duplicate"));
      return;
    }
    if (tags.length >= MAX_TAGS) {
      setTagError(t("identity.tags.tooMany", { max: MAX_TAGS }));
      return;
    }
    setTagError(null);
    // En cas d'échec, la saisie reste dans le champ.
    save(
      { tags: [...tags, value] },
      {
        onSaved: () => {
          setTag("");
          tagInput.current?.focus();
        },
        onFailed: setTagError,
      },
    );
  };

  const removeTag = (index: number) => {
    if (update.isPending) return;
    focusAfterRemoval.current = index;
    setTagError(null);
    save({ tags: tags.filter((_, position) => position !== index) }, { onFailed: setTagError });
  };

  const saveNotes = () => {
    if (update.isPending) return;
    const length = charCount(notes);
    if (length > MAX_NOTES) {
      setNotesError(t("identity.notes.tooLong", { length, max: MAX_NOTES }));
      return;
    }
    setNotesError(null);
    save({ notes }, { onSaved: () => toast.show(t("identity.notes.saved"), "success"), onFailed: setNotesError });
  };

  // aria-disabled plutôt que disabled : un bouton désactivé en cours d'envoi
  // ferait perdre le focus au clavier.
  const busy = update.isPending || undefined;

  return (
    <section className={styles.card} aria-labelledby="notes-title">
      <h2 id="notes-title" className={styles.cardTitle}>
        {t("identity.notes.title")}
      </h2>
      <div>
        <h3 id="tags-title" className={styles.subTitle}>
          {t("identity.tags.label")}
        </h3>
        {tags.length === 0 ? (
          <p className={styles.muted}>{t("identity.tags.none")}</p>
        ) : (
          <ul className={styles.tagList} aria-labelledby="tags-title">
            {tags.map((value, index) => (
              <li key={`${value}-${index}`} className={styles.tag}>
                <span>{value}</span>
                <button
                  type="button"
                  ref={(element) => {
                    removeButtons.current[index] = element;
                  }}
                  className={styles.tagRemove}
                  onClick={() => removeTag(index)}
                  aria-label={t("identity.tags.remove", { tag: value })}
                  aria-disabled={busy}
                >
                  <X aria-hidden />
                </button>
              </li>
            ))}
          </ul>
        )}
        <form className={styles.tagForm} onSubmit={addTag}>
          <label htmlFor="tag-input" className="visually-hidden">
            {t("identity.tags.placeholder")}
          </label>
          <input
            id="tag-input"
            ref={tagInput}
            className={styles.input}
            value={tag}
            onChange={(event) => {
              setTag(event.target.value);
              setTagError(null);
            }}
            placeholder={t("identity.tags.placeholder")}
            autoComplete="off"
            aria-invalid={tagError ? true : undefined}
            aria-describedby={tagError ? "tag-error" : undefined}
          />
          <button type="submit" className="btn" aria-disabled={busy}>
            <Plus aria-hidden />
            {t("identity.tags.add")}
          </button>
        </form>
        {tagError && (
          <p id="tag-error" role="alert" className={styles.errorText}>
            {tagError}
          </p>
        )}
      </div>
      <div>
        <label htmlFor="notes-input" className={styles.subTitle}>
          {t("identity.notes.label")}
        </label>
        <textarea
          id="notes-input"
          className={styles.textarea}
          value={notes}
          onChange={(event) => {
            setNotes(event.target.value);
            setNotesError(null);
          }}
          placeholder={t("identity.notes.placeholder")}
          rows={6}
          aria-invalid={notesError ? true : undefined}
          aria-describedby={notesError ? "notes-error" : undefined}
        />
        {notesError && (
          <p id="notes-error" role="alert" className={styles.errorText}>
            {notesError}
          </p>
        )}
        <div className={styles.actionsRight}>
          <button type="button" className="btn" data-variant="primary" onClick={saveNotes} aria-disabled={busy}>
            <Save aria-hidden />
            {t("identity.notes.save")}
          </button>
        </div>
      </div>
    </section>
  );
}
