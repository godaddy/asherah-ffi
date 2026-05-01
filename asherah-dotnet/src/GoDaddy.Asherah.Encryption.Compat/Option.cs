// ReSharper disable once CheckNamespace — intentionally in LanguageExt namespace
// so consumer code with "using LanguageExt;" works without the real LanguageExt package.
namespace LanguageExt;

/// <summary>
/// Lightweight optional value type, API-compatible with LanguageExt.Option.
/// If you need the full LanguageExt library, replace this package reference
/// with the real LanguageExt.Core NuGet and remove this Option.
/// </summary>
public readonly struct Option<T>
{
    /// <summary>An option with no value (empty).</summary>
    public static readonly Option<T> None = new();

    private readonly T? _value;

    /// <summary>True if this option contains a value.</summary>
    public bool IsSome { get; }

    /// <summary>True if this option is empty.</summary>
    public bool IsNone => !IsSome;

    private Option(T value) { _value = value; IsSome = true; }

    /// <summary>Creates an option that contains <paramref name="value"/>.</summary>
    /// <param name="value">The wrapped value.</param>
    /// <returns>An option in the <see cref="IsSome"/> state.</returns>
    public static Option<T> Some(T value) => new(value);

    /// <summary>Maps the inner value through <paramref name="mapper"/> if present; otherwise returns <see cref="None"/>.</summary>
    public Option<TU> Map<TU>(Func<T, TU> mapper) =>
        IsSome ? Option<TU>.Some(mapper(_value!)) : Option<TU>.None;

    /// <summary>Chains another optional-producing function if present; otherwise returns <see cref="None"/>.</summary>
    public Option<TU> Bind<TU>(Func<T, Option<TU>> binder) =>
        IsSome ? binder(_value!) : Option<TU>.None;

    /// <summary>Produces a result from either branch depending on whether a value exists.</summary>
    public TResult Match<TResult>(Func<T, TResult> some, Func<TResult> none) =>
        IsSome ? some(_value!) : none();

    /// <summary>Invokes <paramref name="some"/> if a value exists; otherwise invokes <paramref name="none"/>.</summary>
    public void Match(Action<T> some, Action none)
    {
        if (IsSome) some(_value!);
        else none();
    }

    /// <summary>Invokes <paramref name="action"/> if a value exists; otherwise does nothing.</summary>
    public void IfSome(Action<T> action)
    {
        if (IsSome) action(_value!);
    }

    /// <summary>Returns the inner value if present; otherwise returns <paramref name="defaultValue"/>.</summary>
    public T IfNone(T defaultValue) => IsSome ? _value! : defaultValue;

    /// <summary>Returns the inner value if present; otherwise invokes <paramref name="defaultFactory"/>.</summary>
    public T IfNone(Func<T> defaultFactory) => IsSome ? _value! : defaultFactory();

    /// <summary>Converts <see cref="Prelude.None"/> to <see cref="None"/>.</summary>
    public static implicit operator Option<T>(OptionNone _) => None;
}

/// <summary>Enables <c>Option&lt;T&gt;.None</c> and <c>None</c> via <c>using static LanguageExt.Prelude;</c></summary>
public readonly struct OptionNone;

/// <summary>Provides <c>Some(value)</c> and <c>None</c> helpers matching LanguageExt.Prelude.</summary>
public static class Prelude
{
    /// <summary>Wraps <paramref name="value"/> as <see cref="Option{T}.Some(T)"/>.</summary>
    public static Option<T> Some<T>(T value) => Option<T>.Some(value);

    /// <summary>Value used with implicit conversion to <see cref="Option{T}"/> for the empty case.</summary>
    public static readonly OptionNone None = new();
}
