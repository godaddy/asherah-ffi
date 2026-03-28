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
    public static readonly Option<T> None = new();

    private readonly T? _value;

    /// <summary>True if this option contains a value.</summary>
    public bool IsSome { get; }

    /// <summary>True if this option is empty.</summary>
    public bool IsNone => !IsSome;

    private Option(T value) { _value = value; IsSome = true; }

    public static Option<T> Some(T value) => new(value);

    public Option<TU> Map<TU>(Func<T, TU> mapper) =>
        IsSome ? Option<TU>.Some(mapper(_value!)) : Option<TU>.None;

    public Option<TU> Bind<TU>(Func<T, Option<TU>> binder) =>
        IsSome ? binder(_value!) : Option<TU>.None;

    public TResult Match<TResult>(Func<T, TResult> some, Func<TResult> none) =>
        IsSome ? some(_value!) : none();

    public void Match(Action<T> some, Action none)
    {
        if (IsSome) some(_value!);
        else none();
    }

    public void IfSome(Action<T> action)
    {
        if (IsSome) action(_value!);
    }

    public T IfNone(T defaultValue) => IsSome ? _value! : defaultValue;

    public T IfNone(Func<T> defaultFactory) => IsSome ? _value! : defaultFactory();

    public static implicit operator Option<T>(OptionNone _) => None;
}

/// <summary>Enables <c>Option&lt;T&gt;.None</c> and <c>None</c> via <c>using static LanguageExt.Prelude;</c></summary>
public readonly struct OptionNone;

/// <summary>Provides <c>Some(value)</c> and <c>None</c> helpers matching LanguageExt.Prelude.</summary>
public static class Prelude
{
    public static Option<T> Some<T>(T value) => Option<T>.Some(value);
    public static readonly OptionNone None = new();
}
